# vpner (русская версия)

`vpner` — это набор утилит для роутеров Entware/OpenWrt (включая Keenetic), объединяющий gRPC‑демон `vpnerd`, консоль `vpnerctl`, вспомогательный `vpshookcli` и скрипты упаковки `.ipk`.

## Возможности

- Управление Xray‑цепочками: импорт ссылок, запуск/остановка, автозапуск, удаление и настройка iptables/ipset.
- Встроенный DNS‑прокси с DoH‑апстримами и `custom-resolve` правилами.
- Хранилище unblock‑правил (домены/IP/CIDR) с синхронизацией в ipset и проверкой перекрытий.
- Пакет `make.sh`, выпускающий `.ipk` для нескольких архитектур.
- Hook‑клиент `vpshookcli`, чтобы мгновенно восстановить правила после очистки iptables.

## Требования

- `/opt` и `opkg` на роутере.
- Пакеты `xray-core`, `ipset`, `iptables` (подтягиваются автоматически через `.ipk`).
- Go ≥ 1.25, если собираете из исходников.

## Установка через `.ipk`

1. Скачайте подходящий `.ipk` из Release и установите:
   ```sh
   opkg update
   opkg install ./vpnerd_<версия>_<арх>.ipk
   ```
2. Файлы окажутся в `/opt/etc/vpner/`:
   - `vpnerd`, `vpner.yaml`, `vpshookcli`;
   - init‑скрипт `/opt/etc/init.d/S95vpnerd`;
   - ndm‑хук `/opt/etc/ndm/netfilter.d/50-vpner` (для Keenetic).
3. Запустите сервис: `/opt/etc/init.d/S95vpnerd start`.

## Настройка DNS на Keenetic

1. Выполнить команду Entware:
   ```sh
   opkg dns-override
   ```
   Она включает перенаправление DNS на локальный сервис.
2. Сохранить конфиг и перезагрузить роутер:
   ```sh
   system configuration save
   reboot
   ```
   После загрузки весь DNS‑трафик пойдёт через `vpnerd`, а ndm‑хук из пакета (`/opt/etc/ndm/netfilter.d/50-vpner`) будет автоматически вызывать `/opt/etc/vpner/vpshookcli --unix /tmp/vpner.sock` при каждой пересборке таблицы `nat`.

## Настройка вручную

- Конфиг: `/opt/etc/vpner/vpner.yaml` (см. `vpner.yaml` в репозитории).
- Файл unblock: `/opt/etc/vpner/vpner_unblock.yaml`.
- Сервис: `/opt/etc/init.d/S95vpnerd {start|stop|restart|status}`.

## CLI

`vpnerctl` ищет настройки в `~/.vpner.cnf`:
```yaml
addr: "router:50051"
password: "secret"
unix: "/tmp/vpner.sock"
```
Ключи `--addr`, `--unix`, `--password`, `--config` переопределяют значения.

### Полезные команды

- `vpnerctl dns manage start|stop|status|restart`
- `vpnerctl unblock list/add/del/import-file/delete-file`
- `vpnerctl interface scan|list|add|del`
- `vpnerctl xray list|create|start|stop|status|delete|autorun`
- `vpnerctl hook restore` — вручную восстановить все правила.

`vpshookcli` — облегчённый клиент для автоматизации (`/opt/etc/vpner/vpshookcli --unix /tmp/vpner.sock`).

## Сборка

```sh
ARCH_LIST="arm64:aarch64-3.10 mipsle:mipsel_24kc" ./make.sh
```
Переменные окружения (`INSTALL_PREFIX`, `DEFAULT_OPKG_ARCH`, `UPX_ARGS` и др.) описаны в основном README.

## CI / Releases

Workflow `.github/workflows/release.yml` собирает `.ipk`, `vpnerctl` и `vpshookcli` для всех архитектур из `ARCH_LIST` и загружает на GitHub Releases.

## Поддержка

Баг‑репорты и PR приветствуются. Указывайте модель роутера, настройки и логи (`/opt/etc/init.d/S95vpnerd status`, `vpnerctl ...`). Перед PR: `gofmt`, `go test ./...`, `make.sh`.
