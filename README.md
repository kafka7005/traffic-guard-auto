# TrafficGuard-Auto

Автоустановщик [TrafficGuard](https://github.com/dotX12/traffic-guard): блокирует сканеры ТСПУ и гос. сети через `iptables` + `ipset`, чтобы сервер не детектировался как VPN. Списки берутся из [shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists).

> ⚠️ Перед установкой убедитесь, что у вас есть доступ к **VNC/KVM-консоли** хостера.

## Установка одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/kafka7005/traffic-guard-auto/main/install.sh | sudo bash
```

Скрипт спросит набор списков, логирование и автообновление. Для установки без вопросов:

```bash
# Стандарт: antiscanner + government_networks
curl -fsSL https://raw.githubusercontent.com/kafka7005/traffic-guard-auto/main/install.sh | sudo bash -s -- --preset standard -y

# Полный: + skipa
curl -fsSL https://raw.githubusercontent.com/kafka7005/traffic-guard-auto/main/install.sh | sudo bash -s -- --preset full -y

# Selectel: government_networks зафиксирован на коммите 26929c9 (без EdgeCenter)
curl -fsSL https://raw.githubusercontent.com/kafka7005/traffic-guard-auto/main/install.sh | sudo bash -s -- --preset selectel -y
```

### Параметры

| Параметр | Описание |
|---|---|
| `--preset standard\|full\|selectel` | Набор списков (по умолчанию `standard`) |
| `--no-logging` | Без логирования блокировок |
| `--no-auto-update` | Без ежедневного автообновления списков |
| `--allow <IP/CIDR>` | Добавить в белый список (можно несколько раз) |
| `-y`, `--yes` | Не задавать вопросов |

## Что делает установщик

1. Ставит зависимости (`ipset`, `iptables-persistent`, `rsyslog`, `whois` и др.)
2. Ставит бинарник `traffic-guard` официальным скриптом
3. **Добавляет ваш текущий SSH-IP в белый список**, чтобы не потерять доступ
4. Применяет списки и сохраняет правила
5. Создаёт systemd-таймер: переприменение после перезагрузки и обновление списков каждый день ~04:00
6. Ставит команду `tgctl`

## Управление

```
tgctl                  интерактивное меню
tgctl status           статус и счётчики
tgctl update           обновить списки
tgctl top [N]          топ сканеров
tgctl logs [v4|v6|csv] логи в реальном времени
tgctl ban <IP/CIDR>    заблокировать (сохраняется при обновлениях)
tgctl unban <IP/CIDR>  разблокировать
tgctl allow <IP/CIDR>  белый список — никогда не блокировать
tgctl disallow <IP>    убрать из белого списка
tgctl test <IP>        проверить IP
tgctl preset <name>    сменить набор списков
tgctl off / on         аварийно выключить / включить
tgctl self-update      обновить tgctl
tgctl uninstall        удалить полностью
```

Файлы конфигурации: `/etc/traffic-guard-auto/` (`config`, `whitelist.txt`, `custom.list`).

## Аварийное восстановление

Если пропал SSH — зайдите через VNC-консоль хостера:

```bash
tgctl off
# или
iptables -D INPUT -j SCANNERS-BLOCK
```

## Заметки

- **Selectel**: в марте 2026 в `government_networks.list` добавили EdgeCenter (AS210756), что ломает сеть Selectel. Используйте пресет `selectel`.
- Автообновление тянет свежие списки из `main` — если новая версия что-то ломает, отключите его: `systemctl disable --now traffic-guard-auto.timer`.
- Белый список реализован правилами `RETURN` в начале цепочки `SCANNERS-BLOCK` — трафик идёт дальше по вашим обычным правилам (UFW и т.д.).
