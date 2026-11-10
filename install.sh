#!/usr/bin/env bash
# =============================================================================
#  TrafficGuard-Auto — установщик и менеджер TrafficGuard (iptables + ipset)
#
#  Установка одной командой:
#    curl -fsSL https://raw.githubusercontent.com/kafka7005/traffic-guard-auto/main/install.sh | sudo bash
#
#  С параметрами (без вопросов):
#    curl -fsSL https://raw.githubusercontent.com/kafka7005/traffic-guard-auto/main/install.sh | sudo bash -s -- --preset selectel -y
#
#  После установки доступна команда: tgctl
# =============================================================================

REPO_RAW="${TG_REPO_RAW:-https://raw.githubusercontent.com/kafka7005/traffic-guard-auto/main}"

LISTS_BASE="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public"
GOV_PINNED="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/26929c9db71443a18c4369299ba60673a792c2ac/public/government_networks.list"
TG_INSTALLER="https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh"

CONF_DIR=/etc/traffic-guard-auto
CONF="$CONF_DIR/config"
WHITELIST="$CONF_DIR/whitelist.txt"
CUSTOM_LIST="$CONF_DIR/custom.list"
BIN=/usr/local/bin/tgctl
UNIT=traffic-guard-auto
AGG_CSV=/var/log/iptables-scanners-aggregate.csv
SET4=SCANNERS-BLOCK-V4
SET6=SCANNERS-BLOCK-V6
CHAIN=SCANNERS-BLOCK

# --- defaults (перезаписываются конфигом и аргументами) ---
PRESET=""
LOGGING=1
AUTO_UPDATE=1
ASSUME_YES=0
EXTRA_ALLOW=()

# --- вывод ---
if [ -t 1 ]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[36m'; C_W=$'\e[1m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_W=""; C_0=""
fi
info() { echo "${C_B}[*]${C_0} $*"; }
ok()   { echo "${C_G}[+]${C_0} $*"; }
warn() { echo "${C_Y}[!]${C_0} $*" >&2; }
die()  { echo "${C_R}[x]${C_0} $*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "Нужны права root (запустите через sudo)."; }

has_tty() { [ -r /dev/tty ] && [ -w /dev/tty ] && { : </dev/tty; } 2>/dev/null; }
ask() { # ask "вопрос" default -> печатает ответ
  local q="$1" def="$2" a=""
  if [ "$ASSUME_YES" -eq 1 ] || ! has_tty; then echo "$def"; return; fi
  printf '%s' "$q" >/dev/tty
  read -r a </dev/tty || a=""
  echo "${a:-$def}"
}
confirm() { # confirm "вопрос" -> 0 если да
  local a; a="$(ask "$1 [y/N]: " "n")"
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [[ "$a" =~ ^[YyДд] ]]
}

tg_bin() {
  if have traffic-guard; then command -v traffic-guard
  elif [ -x /usr/local/bin/traffic-guard ]; then echo /usr/local/bin/traffic-guard
  else echo ""; fi
}

is_ipv6() { [[ "$1" == *:* ]]; }
valid_addr() { # IPv4/IPv6 с необязательной маской
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || [[ "$1" =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ && "$1" == *:* ]]
}
ipt_for() { if is_ipv6 "$1"; then echo ip6tables; else echo iptables; fi; }
set_for() { if is_ipv6 "$1"; then echo "$SET6"; else echo "$SET4"; fi; }

# --- конфиг ---
load_conf() {
  # shellcheck disable=SC1090
  [ -f "$CONF" ] && . "$CONF"
  return 0
}
save_conf() {
  mkdir -p "$CONF_DIR"
  cat >"$CONF" <<EOF
# TrafficGuard-Auto config
# PRESET: standard | full | selectel
PRESET=$PRESET
LOGGING=$LOGGING
AUTO_UPDATE=$AUTO_UPDATE
EOF
  [ -f "$WHITELIST" ] || printf '# Белый список: IP/подсети, которые никогда не блокируются (по одному в строке)\n' >"$WHITELIST"
  [ -f "$CUSTOM_LIST" ] || printf '# Свои IP/подсети для блокировки (по одному в строке)\n' >"$CUSTOM_LIST"
}

build_urls() {
  case "$PRESET" in
    standard) echo "$LISTS_BASE/antiscanner.list"; echo "$LISTS_BASE/government_networks.list" ;;
    full)     echo "$LISTS_BASE/antiscanner.list"; echo "$LISTS_BASE/government_networks.list"; echo "$LISTS_BASE/skipa.list" ;;
    selectel) echo "$LISTS_BASE/antiscanner.list"; echo "$GOV_PINNED"; echo "$LISTS_BASE/skipa.list" ;;
    *) die "Неизвестный пресет: '$PRESET' (standard | full | selectel)" ;;
  esac
  if [ -f "$CUSTOM_LIST" ] && grep -qvE '^\s*(#|$)' "$CUSTOM_LIST"; then
    echo "file://$CUSTOM_LIST"
  fi
}

list_entries() { [ -f "$1" ] && grep -vE '^\s*(#|$)' "$1" | awk '{print $1}'; }

# --- SSH-защита: IP текущего SSH-клиента ---
detect_ssh_ip() {
  local ip=""
  if [ -n "${SSH_CLIENT:-}" ]; then ip="${SSH_CLIENT%% *}"
  elif [ -n "${SSH_CONNECTION:-}" ]; then ip="${SSH_CONNECTION%% *}"
  else ip="$(who -m 2>/dev/null | sed -n 's/.*(\([^)]*\)).*/\1/p' | head -n1)"
  fi
  ip="${ip#::ffff:}"
  valid_addr "$ip" && echo "$ip"
}

whitelist_add() {
  local e="$1"
  valid_addr "$e" || { warn "Некорректный адрес: $e"; return 1; }
  mkdir -p "$CONF_DIR"; touch "$WHITELIST"
  grep -qxF "$e" "$WHITELIST" || echo "$e" >>"$WHITELIST"
}

apply_whitelist() {
  local e cmd
  while read -r e; do
    [ -n "$e" ] || continue
    cmd="$(ipt_for "$e")"
    have "$cmd" || continue
    "$cmd" -n -L "$CHAIN" >/dev/null 2>&1 || continue
    "$cmd" -C "$CHAIN" -s "$e" -j RETURN 2>/dev/null || "$cmd" -I "$CHAIN" 1 -s "$e" -j RETURN
  done < <(list_entries "$WHITELIST")
}

save_rules() {
  if have netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif have service && [ -f /etc/sysconfig/iptables ]; then
    service iptables save >/dev/null 2>&1 || true
    service ip6tables save >/dev/null 2>&1 || true
  fi
  have ipset && ipset save >/etc/ipset.conf 2>/dev/null || true
}

# --- применение правил ---
cmd_apply() {
  need_root; load_conf
  [ -n "$PRESET" ] || PRESET=standard
  local tg; tg="$(tg_bin)"; [ -n "$tg" ] || die "traffic-guard не установлен. Запустите установку заново."
  local args=() u
  while read -r u; do args+=(-u "$u"); done < <(build_urls)
  [ "$LOGGING" = "1" ] && args+=(--enable-logging)
  info "Применяю списки (пресет: $PRESET)…"
  "$tg" full "${args[@]}" </dev/null || die "traffic-guard завершился с ошибкой."
  apply_whitelist
  save_rules
  ok "Правила применены. Заблокировано подсетей: IPv4=$(set_count "$SET4"), IPv6=$(set_count "$SET6")"
}

set_count() { ipset list "$1" -t 2>/dev/null | awk -F': ' '/Number of entries/{print $2}' | grep . || echo 0; }
drop_count() {
  local s=0 c
  for c in iptables ip6tables; do
    have "$c" || continue
    s=$(( s + $("$c" -L "$CHAIN" -v -n -x 2>/dev/null | awk '$3=="DROP"{s+=$1} END{print s+0}') ))
  done
  echo "$s"
}

# --- установка ---
install_deps() {
  info "Устанавливаю зависимости…"
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true
    apt-get update -qq </dev/null || warn "apt-get update завершился с ошибкой"
    apt-get install -y -qq curl wget rsyslog ipset iptables iptables-persistent netfilter-persistent whois logrotate </dev/null \
      || die "Не удалось установить пакеты."
    apt-get install -y -qq ipset-persistent </dev/null >/dev/null 2>&1 || true
  elif have dnf || have yum; then
    local pm; pm="$(have dnf && echo dnf || echo yum)"
    $pm install -y -q curl wget rsyslog ipset iptables iptables-services whois logrotate </dev/null \
      || die "Не удалось установить пакеты."
    systemctl enable iptables ip6tables >/dev/null 2>&1 || true
  else
    die "Поддерживаются только Debian/Ubuntu (apt) и RHEL/CentOS/Alma/Rocky (dnf/yum)."
  fi
  systemctl enable --now rsyslog >/dev/null 2>&1 || true
  ok "Зависимости установлены."
}

install_binary() {
  info "Устанавливаю traffic-guard…"
  curl -fsSL "$TG_INSTALLER" | bash </dev/null || die "Не удалось установить traffic-guard."
  [ -n "$(tg_bin)" ] || die "traffic-guard не найден после установки."
  ok "traffic-guard: $("$(tg_bin)" --version 2>/dev/null | head -n1)"
}

install_manager() {
  if [ -f "$0" ] && grep -q 'TrafficGuard-Auto' "$0" 2>/dev/null && [ "$(readlink -f "$0")" != "$BIN" ]; then
    install -m 0755 "$0" "$BIN"
  elif [ "$(readlink -f "$0" 2>/dev/null)" != "$BIN" ]; then
    curl -fsSL "$REPO_RAW/install.sh" -o "$BIN.tmp" && mv -f "$BIN.tmp" "$BIN" && chmod 0755 "$BIN" \
      || { rm -f "$BIN.tmp"; warn "Не удалось установить команду tgctl"; return; }
  fi
  ok "Команда управления: ${C_W}tgctl${C_0}"
}

install_units() {
  cat >/etc/systemd/system/$UNIT.service <<EOF
[Unit]
Description=TrafficGuard-Auto: apply/update block lists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN apply
EOF
  cat >/etc/systemd/system/$UNIT.timer <<EOF
[Unit]
Description=TrafficGuard-Auto: daily list update and re-apply after boot

[Timer]
OnBootSec=1min
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  if [ "$AUTO_UPDATE" = "1" ]; then
    systemctl enable --now $UNIT.timer >/dev/null 2>&1 && ok "Автообновление списков: ежедневно ~04:00 и после перезагрузки."
  else
    systemctl disable --now $UNIT.timer >/dev/null 2>&1 || true
    info "Автообновление списков отключено."
  fi
}

wizard() {
  has_tty || return 0
  [ "$ASSUME_YES" -eq 1 ] && return 0
  if [ -z "$PRESET" ]; then
    cat >/dev/tty <<EOF

${C_W}Выберите набор списков:${C_0}
  1) standard  — antiscanner + government_networks (по умолчанию)
  2) full      — + skipa
  3) selectel  — для Selectel: government_networks зафиксирован на коммите 26929c9 (без EdgeCenter) + skipa
EOF
    case "$(ask "Ваш выбор [1]: " 1)" in
      2|full) PRESET=full ;;
      3|selectel) PRESET=selectel ;;
      *) PRESET=standard ;;
    esac
  fi
  [[ "$(ask "Включить логирование блокировок? [Y/n]: " y)" =~ ^[NnНн] ]] && LOGGING=0
  [[ "$(ask "Включить ежедневное автообновление списков? [Y/n]: " y)" =~ ^[NnНн] ]] && AUTO_UPDATE=0
  return 0
}

cmd_install() {
  need_root
  local p="$PRESET" l="$LOGGING" a="$AUTO_UPDATE"
  load_conf
  # аргументы командной строки важнее сохранённого конфига
  [ -n "$p" ] && PRESET="$p"
  [ "$_SET_LOGGING" = 1 ] && LOGGING="$l"
  [ "$_SET_AUTO" = 1 ] && AUTO_UPDATE="$a"
  [ -f "$CONF" ] && [ -z "$p" ] && ASSUME_YES_WIZ=1

  echo "${C_W}=== TrafficGuard-Auto: установка ===${C_0}"
  warn "Убедитесь, что у вас есть доступ к VNC/KVM-консоли хостера на случай потери SSH."

  [ "${ASSUME_YES_WIZ:-0}" = 1 ] || wizard
  [ -n "$PRESET" ] || PRESET=standard
  info "Пресет: $PRESET | логирование: $LOGGING | автообновление: $AUTO_UPDATE"

  save_conf

  local sship; sship="$(detect_ssh_ip)"
  if [ -n "$sship" ]; then
    whitelist_add "$sship" && ok "Ваш текущий SSH-IP $sship добавлен в белый список."
  else
    warn "Не удалось определить IP SSH-клиента. Добавьте его вручную: tgctl allow <IP>"
  fi
  local e; for e in "${EXTRA_ALLOW[@]}"; do whitelist_add "$e" && ok "В белый список: $e"; done

  install_deps
  install_binary
  install_manager
  cmd_apply
  install_units

  echo
  ok "${C_W}Готово!${C_0}"
  cat <<EOF

  tgctl            — интерактивное меню
  tgctl status     — статус
  tgctl help       — все команды
  Аварийно (если пропал доступ, через VNC): ${C_W}tgctl off${C_0}  или  iptables -D INPUT -j $CHAIN

EOF
}

# --- управление ---
cmd_status() {
  load_conf
  echo "${C_W}=== TrafficGuard-Auto ===${C_0}"
  echo "Пресет:          ${PRESET:-?}"
  echo "Логирование:     $([ "$LOGGING" = 1 ] && echo вкл || echo выкл)"
  echo "Автообновление:  $(systemctl is-enabled $UNIT.timer 2>/dev/null || echo нет)"
  echo "Следующий запуск: $(systemctl show $UNIT.timer -p NextElapseUSecRealtime --value 2>/dev/null || echo -)"
  echo "traffic-guard:   $([ -n "$(tg_bin)" ] && "$(tg_bin)" --version 2>/dev/null | head -n1 || echo 'не установлен')"
  if iptables -C INPUT -j "$CHAIN" 2>/dev/null; then echo "Защита:          ${C_G}активна${C_0}"; else echo "Защита:          ${C_R}выключена${C_0}"; fi
  echo "Подсетей IPv4:   $(set_count "$SET4")"
  echo "Подсетей IPv6:   $(set_count "$SET6")"
  echo "Отброшено пакетов: $(drop_count)"
  echo "Белый список:    $(list_entries "$WHITELIST" | tr '\n' ' ')"
}

cmd_top() {
  [ -f "$AGG_CSV" ] || die "Нет $AGG_CSV (логирование выключено или ещё нет данных)."
  head -n "${1:-21}" "$AGG_CSV" | column -t -s '|'
}

cmd_logs() {
  local f=/var/log/iptables-scanners-ipv4.log
  [ "${1:-}" = "v6" ] && f=/var/log/iptables-scanners-ipv6.log
  [ "${1:-}" = "csv" ] && f="$AGG_CSV"
  [ -f "$f" ] || die "Нет файла $f"
  tail -n 50 -f "$f"
}

cmd_ban() {
  need_root; local e="$1"
  valid_addr "$e" || die "Укажите IP или подсеть: tgctl ban 1.2.3.4"
  ipset add "$(set_for "$e")" "$e" -exist || die "Не удалось добавить $e"
  mkdir -p "$CONF_DIR"; touch "$CUSTOM_LIST"
  grep -qxF "$e" "$CUSTOM_LIST" || echo "$e" >>"$CUSTOM_LIST"
  save_rules; ok "Заблокирован: $e (сохранён в $CUSTOM_LIST)"
}

cmd_unban() {
  need_root; local e="$1"
  valid_addr "$e" || die "Укажите IP или подсеть: tgctl unban 1.2.3.4"
  [ -f "$CUSTOM_LIST" ] && sed -i "\#^${e//./\\.}\$#d" "$CUSTOM_LIST"
  if ipset del "$(set_for "$e")" "$e" 2>/dev/null; then
    save_rules; ok "Разблокирован: $e"
  elif ipset test "$(set_for "$e")" "$e" 2>/dev/null; then
    warn "$e входит в более широкую подсеть из списков. Используйте: tgctl allow $e"
  else
    info "$e не заблокирован."
  fi
}

cmd_allow() {
  need_root; whitelist_add "$1" || die "Укажите IP или подсеть: tgctl allow 1.2.3.4"
  apply_whitelist; save_rules; ok "В белом списке: $1"
}

cmd_disallow() {
  need_root; local e="$1" cmd
  valid_addr "$e" || die "Укажите IP или подсеть."
  [ -f "$WHITELIST" ] && sed -i "\#^${e//./\\.}\$#d" "$WHITELIST"
  cmd="$(ipt_for "$e")"
  while "$cmd" -D "$CHAIN" -s "$e" -j RETURN 2>/dev/null; do :; done
  save_rules; ok "Удалён из белого списка: $e"
}

cmd_test() {
  local e="$1"; valid_addr "$e" || die "Укажите IP."
  if ipset test "$(set_for "$e")" "$e" >/dev/null 2>&1; then
    echo "${C_R}$e — в списке блокировки${C_0}"
    list_entries "$WHITELIST" | grep -qxF "$e" && echo "  (но есть в белом списке — пропускается)"
  else
    echo "${C_G}$e — не заблокирован${C_0}"
  fi
}

cmd_off() {
  need_root
  while iptables -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
  while ip6tables -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
  systemctl stop $UNIT.timer >/dev/null 2>&1 || true
  save_rules
  ok "Защита выключена (правила удалены из INPUT, автообновление остановлено). Включить: tgctl on"
}

cmd_on() {
  load_conf; cmd_apply
  [ "$AUTO_UPDATE" = "1" ] && systemctl start $UNIT.timer >/dev/null 2>&1 || true
}

cmd_preset() {
  need_root; load_conf
  case "$1" in standard|full|selectel) PRESET="$1" ;; *) die "Пресеты: standard | full | selectel" ;; esac
  save_conf; cmd_apply
}

cmd_uninstall() {
  need_root
  confirm "Полностью удалить TrafficGuard и все правила?" || { info "Отменено."; return; }
  systemctl disable --now $UNIT.timer $UNIT.service >/dev/null 2>&1 || true
  systemctl disable --now antiscan-aggregate.timer antiscan-aggregate.service >/dev/null 2>&1 || true
  local c
  for c in iptables ip6tables; do
    have "$c" || continue
    while "$c" -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
    "$c" -F "$CHAIN" 2>/dev/null; "$c" -X "$CHAIN" 2>/dev/null
  done
  for c in "$SET4" "$SET6"; do ipset flush "$c" 2>/dev/null; ipset destroy "$c" 2>/dev/null; done
  rm -f /usr/local/bin/traffic-guard /usr/local/bin/antiscan-aggregate-logs.sh \
        /etc/systemd/system/antiscan-aggregate.* /etc/systemd/system/$UNIT.* \
        /etc/rsyslog.d/10-iptables-scanners.conf /etc/logrotate.d/iptables-scanners
  rm -rf "$CONF_DIR"
  systemctl daemon-reload; systemctl restart rsyslog >/dev/null 2>&1 || true
  save_rules
  rm -f "$BIN"
  ok "TrafficGuard удалён."
}

cmd_selfupdate() {
  need_root
  curl -fsSL "$REPO_RAW/install.sh" -o "$BIN.tmp" && bash -n "$BIN.tmp" && mv -f "$BIN.tmp" "$BIN" && chmod 0755 "$BIN" \
    && ok "tgctl обновлён." || { rm -f "$BIN.tmp"; die "Не удалось обновить tgctl."; }
}

cmd_help() {
  cat <<EOF
${C_W}tgctl${C_0} — управление TrafficGuard

  tgctl                 интерактивное меню
  tgctl status          статус защиты и счётчики
  tgctl update          перезагрузить списки и применить правила (= apply)
  tgctl top [N]         топ сканеров из агрегированного лога
  tgctl logs [v4|v6|csv] логи в реальном времени
  tgctl ban <IP/CIDR>   заблокировать вручную (сохраняется при обновлениях)
  tgctl unban <IP/CIDR> снять ручную блокировку
  tgctl allow <IP/CIDR> добавить в белый список (никогда не блокировать)
  tgctl disallow <IP>   убрать из белого списка
  tgctl test <IP>       проверить, заблокирован ли IP
  tgctl preset <name>   сменить набор списков: standard | full | selectel
  tgctl off             аварийно выключить защиту
  tgctl on              включить защиту обратно
  tgctl self-update     обновить сам tgctl из репозитория
  tgctl reinstall       переустановить
  tgctl uninstall       полностью удалить

Файлы: $CONF, $WHITELIST, $CUSTOM_LIST
EOF
}

cmd_menu() {
  has_tty || { cmd_help; return; }
  local ch ip
  while true; do
    clear 2>/dev/null
    cmd_status
    cat <<EOF

  1) Топ атак            6) Белый список: добавить
  2) Логи IPv4 (live)    7) Сменить пресет
  3) Логи IPv6 (live)    8) Выключить / включить защиту
  4) Бан / разбан IP     9) Переустановить
  5) Обновить списки     10) Удалить
  0) Выход
EOF
    read -r -p "> " ch </dev/tty || return
    case "$ch" in
      1) cmd_top 21; read -r -p "Enter…" _ </dev/tty ;;
      2) cmd_logs v4 ;;
      3) cmd_logs v6 ;;
      4) read -r -p "IP/подсеть: " ip </dev/tty
         read -r -p "b — бан, u — разбан: " ch </dev/tty
         if [ "$ch" = u ]; then cmd_unban "$ip"; else cmd_ban "$ip"; fi
         read -r -p "Enter…" _ </dev/tty ;;
      5) cmd_apply; read -r -p "Enter…" _ </dev/tty ;;
      6) read -r -p "IP/подсеть: " ip </dev/tty; cmd_allow "$ip"; read -r -p "Enter…" _ </dev/tty ;;
      7) read -r -p "standard | full | selectel: " ip </dev/tty; cmd_preset "$ip"; read -r -p "Enter…" _ </dev/tty ;;
      8) if iptables -C INPUT -j "$CHAIN" 2>/dev/null; then cmd_off; else cmd_on; fi; read -r -p "Enter…" _ </dev/tty ;;
      9) cmd_install; read -r -p "Enter…" _ </dev/tty ;;
      10) cmd_uninstall; return ;;
      0|q) return ;;
    esac
  done
}

# --- точка входа ---
main() {
  local cmd=""
  _SET_LOGGING=0; _SET_AUTO=0
  # Если запущено как tgctl без аргументов — меню; через curl|bash — установка.
  if [ "$(basename -- "$0")" = "tgctl" ]; then cmd=menu; else cmd=install; fi

  local pos=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --preset) PRESET="${2:-}"; shift ;;
      --preset=*) PRESET="${1#*=}" ;;
      --standard|--full|--selectel) PRESET="${1#--}" ;;
      --no-logging) LOGGING=0; _SET_LOGGING=1 ;;
      --logging) LOGGING=1; _SET_LOGGING=1 ;;
      --no-auto-update) AUTO_UPDATE=0; _SET_AUTO=1 ;;
      --auto-update) AUTO_UPDATE=1; _SET_AUTO=1 ;;
      --allow) EXTRA_ALLOW+=("${2:-}"); shift ;;
      --allow=*) EXTRA_ALLOW+=("${1#*=}") ;;
      -y|--yes) ASSUME_YES=1 ;;
      -h|--help) cmd=help ;;
      *) pos+=("$1") ;;
    esac
    shift
  done
  if [ -n "$PRESET" ]; then
    case "$PRESET" in standard|full|selectel) ;; *) die "Неизвестный пресет: $PRESET" ;; esac
  fi
  [ ${#pos[@]} -gt 0 ] && { cmd="${pos[0]}"; pos=("${pos[@]:1}"); }

  case "$cmd" in
    install|reinstall) cmd_install ;;
    apply|update)      cmd_apply ;;
    status)            cmd_status ;;
    top)               cmd_top "$(( ${pos[0]:-20} + 1 ))" ;;
    logs|log)          cmd_logs "${pos[0]:-v4}" ;;
    ban)               cmd_ban "${pos[0]:-}" ;;
    unban)             cmd_unban "${pos[0]:-}" ;;
    allow|whitelist)   cmd_allow "${pos[0]:-}" ;;
    disallow)          cmd_disallow "${pos[0]:-}" ;;
    test|check)        cmd_test "${pos[0]:-}" ;;
    preset)            cmd_preset "${pos[0]:-}" ;;
    off|disable)       cmd_off ;;
    on|enable)         cmd_on ;;
    self-update)       cmd_selfupdate ;;
    uninstall|remove)  cmd_uninstall ;;
    menu)              cmd_menu ;;
    help)              cmd_help ;;
    *) cmd_help; exit 1 ;;
  esac
}

# Весь скрипт обёрнут в main, чтобы при `curl | bash` он был прочитан целиком до выполнения.
main "$@"
