# vpner

[Read in English](README.md)

`vpner` — это сетевой стек для роутеров и Linux-хостов в стиле Entware/OpenWrt. Он объединяет демон для управления DNS, Xray, iptables/ipset и unblock-правилами, а также небольшие CLI-утилиты для администрирования и router hooks.

В первую очередь проект рассчитан на роутеры с `/opt`, и особенно хорошо подходит для Keenetic + Entware.

## Что входит в проект

- `vpnerd` — основной демон. Загружает `vpner.yaml`, поднимает gRPC, запускает DNS, восстанавливает routing и управляет Xray-цепочками.
- `vpnerctl` — CLI для управления `vpnerd` по UNIX-сокету или TCP.
- `vpnerhookcli` — вспомогательная утилита для хуков роутера. Повторно применяет routing после пересборки таблиц `nat` или `mangle`.
- `make.sh` — скрипт сборки `.ipk`-пакетов.

## Что умеет `vpner`

- Создавать и управлять Xray-цепочками из ссылок `vmess://`, `vless://` и `ss://`.
- Поднимать локальный DNS-сервис с DoH-апстримами и выборочным `custom-resolve`.
- Хранить unblock-правила в YAML и синхронизировать их в `ipset`.
- Восстанавливать iptables/ipset-маршрутизацию после очистки таблиц роутером.
- Работать как в режиме обычного `REDIRECT`, так и в режиме `TPROXY`.

## Требования

- Linux-роутер или хост с root-доступом.
- Файловая структура `/opt`, если используется пакетная установка.
- `opkg` для установки `.ipk`.
- `xray` в `PATH` на роутере.
- `iptables`, `ipset` и `ip` на роутере.
- Go `1.25.4+`, если собираете из исходников.

## Рекомендуемая установка: `.ipk`

1. Скачайте пакет нужной архитектуры из Releases.
2. Скопируйте его на роутер и установите:

   ```sh
   opkg update
   opkg install ./vpnerd_<версия>_<архитектура>.ipk
   ```

3. После установки на роутере появятся:

   | Путь | Назначение |
   | --- | --- |
   | `/opt/etc/vpner/vpnerd` | Бинарник демона |
   | `/opt/etc/vpner/vpnerhookcli` | Бинарник hook-клиента |
   | `/opt/etc/vpner/vpner.yaml.example` | Шаблон конфига |
   | `/opt/etc/vpner/vpner.yaml` | Рабочий конфиг, создаётся при первой установке, если его нет |
   | `/opt/etc/vpner/vpner_unblock.yaml` | Файл постоянных unblock-правил, создаётся при первой записи правил |
   | `/opt/etc/vpner/xray/` | Каталог конфигов Xray |
   | `/opt/etc/init.d/S95vpnerd` | Init-скрипт |
   | `/opt/etc/ndm/netfilter.d/50-vpner` | Хук для Keenetic, восстанавливающий routing после пересборки `nat`/`mangle` |

4. Отредактируйте `/opt/etc/vpner/vpner.yaml`.
5. Запустите сервис:

   ```sh
   /opt/etc/init.d/S95vpnerd start
   ```

Полезные команды:

```sh
/opt/etc/init.d/S95vpnerd stop
/opt/etc/init.d/S95vpnerd restart
/opt/etc/init.d/S95vpnerd status
tail -f /opt/var/log/vpnerd.log
```

## Особенности для Keenetic

### Перенаправление DNS в Entware

Если `vpner` запускается на Keenetic с Entware, после установки включите перенаправление DNS Keenetic в `/opt`.
Команды ниже нужно выполнять в **CLI Keenetic / Web CLI**, а не внутри Entware shell:

```sh
opkg dns-override
system configuration save
reboot
```

После перезагрузки DNS клиентов локальной сети будет обслуживать `vpnerd`, а установленный NDM-хук будет автоматически вызывать `vpnerhookcli` каждый раз, когда Keenetic пересобирает `nat` или `mangle`.

### TPROXY на Keenetic

Если нужен прозрачный прокси-режим `TPROXY`, включите:

```yaml
network:
  enable-tproxy: true
```

Важно для Keenetic:

- `TPROXY` заработает только если в `Общие системные настройки -> Параметры компонентов` установлен модуль **Kernel modules for Netfilter**.
- На практике `vpnerd` требует поддержку модулей ядра, стоящих за `xt_TPROXY` и `xt_socket`.
- Если нужных netfilter-модулей нет или прошивка их не поддерживает, `vpnerd` запишет предупреждение в лог и автоматически переключится на режим `REDIRECT`.

Если на Keenetic `enable-tproxy: true` ничего не меняет, первым делом проверяйте именно этот компонент.

## Конфигурация

Основной конфиг лежит в `/opt/etc/vpner/vpner.yaml`.

Минимальный пример:

```yaml
dnsServer:
  port: 53
  max-concurrent-connections: 100
  verbose: false
  running: true
  custom-resolve: {}

doh:
  servers:
    - "https://dns.google/dns-query"
    - "https://cloudflare-dns.com/dns-query"
  resolvers:
    - "1.1.1.1"
    - "8.8.8.8"
  cache-ttl: 300

grpc:
  tcp:
    enabled: true
    address: ":50051"
    auth: true
  unix:
    enabled: true
    path: "/tmp/vpner.sock"
  auth:
    password: "secret123"

unblock-rules-path: "/opt/etc/vpner/vpner_unblock.yaml"

network:
  lan-interfaces:
    - "br0"
  enable-ipv6: false
  enable-tproxy: false
  ipset-debug: false
  ipset-stale-queries: 100
```

Ключевые параметры:

- `dnsServer.running` — автоматически запускать встроенный DNS-сервер при старте демона.
- `dnsServer.custom-resolve` — направлять отдельные домены на конкретные резолверы вида `1.1.1.1:53`.
- `doh.servers` — список DoH-апстримов.
- `doh.resolvers` — обычные DNS-резолверы для bootstrap/fallback-логики.
- `grpc.tcp.enabled` — открыть gRPC по TCP.
- `grpc.tcp.auth` — требовать пароль из `grpc.auth.password` на TCP-listener.
- `grpc.unix.path` — путь к локальному UNIX-сокету для управления с роутера.
- `network.lan-interfaces` — LAN-интерфейсы, трафик с которых должен перехватываться.
- `network.enable-ipv6` — включить IPv6 iptables/ipset/ip-rule.
- `network.enable-tproxy` — переключить Xray и routing в прозрачный режим, если ядро это поддерживает.
- `network.ipset-stale-queries` — задержка перед удалением IP, привязанных к доменам, из `ipset`.

## Файл unblock-правил

Параметр `unblock-rules-path` указывает на YAML-файл с доменами, IP и CIDR, сгруппированными по типу VPN и chain name.

Пример:

```yaml
Xray:
  xray1:
    - "*.netflix.com"
    - "203.0.113.45"
OpenVPN:
  myvpn:
    - "*.example.org"
```

Что важно:

- Доменные шаблоны должны проходить валидацию проекта.
- IP и CIDR сохраняются как статические записи в `ipset`.
- Файл обновляется автоматически при добавлении и удалении правил через `vpnerctl`.

## Управление демоном

`vpnerd` автоматически запускает:

- DNS-сервис, если `dnsServer.running: true`
- все Xray-цепочки с `auto_run: true`
- восстановление routing для уже существующих цепочек

Стандартная команда запуска демона:

```sh
/opt/etc/vpner/vpnerd --config /opt/etc/vpner/vpner.yaml
```

## `vpnerctl`

`.ipk`-пакет ставит `vpnerd` и `vpnerhookcli`, но **не ставит `vpnerctl`**. Если нужен CLI для администрирования, соберите его отдельно.

Сборка:

```sh
go build -o vpnerctl ./cmd/vpnerctl
```

Необязательный конфиг CLI: `~/.vpner.cnf`

```yaml
unix: "/tmp/vpner.sock"
addr: "router.example:50051"
password: "secret123"
timeout: "5s"
default-chain: "xray1"
```

Важно:

- Если указан `unix`, `vpnerctl` в первую очередь подключается именно к UNIX-сокету.
- Если не указаны ни `unix`, ни `addr`, используются значения по умолчанию: `/tmp/vpner.sock` и `:50051`.
- TCP gRPC сейчас работает без транспортного шифрования. Не выставляйте его в недоверенную сеть без VPN/SSH-туннеля.

Основные команды:

```sh
vpnerctl dns status
vpnerctl dns restart

vpnerctl xray list
vpnerctl xray create 'vless://...'
vpnerctl xray start xray1
vpnerctl xray stop xray1
vpnerctl xray autorun xray1 --enable
vpnerctl xray delete xray1

vpnerctl interface scan
vpnerctl interface list

vpnerctl unblock list
vpnerctl unblock add --chain xray1 "*.netflix.com"
vpnerctl unblock del "*.netflix.com"
vpnerctl unblock import-file --chain xray1 --file rules.txt
vpnerctl unblock delete-file --file rules.txt
```

## `vpnerhookcli`

`vpnerhookcli` предназначен для автоматизации и router hooks. В обычной установке на Keenetic вручную его обычно запускать не нужно, потому что пакет уже ставит `/opt/etc/ndm/netfilter.d/50-vpner`.

Пример ручного вызова:

```sh
/opt/etc/vpner/vpnerhookcli --unix /tmp/vpner.sock --family ipv4 --table nat
```

Допустимые значения:

- `--family`: `ipv4`, `ipv6`, `v4`, `v6`
- `--table`: `nat`, `mangle`

## Сборка из исходников

Сборка всех пользовательских бинарников:

```sh
go build -o vpnerd ./cmd/vpnerd
go build -o vpnerhookcli ./cmd/vpnerhookcli
go build -o vpnerctl ./cmd/vpnerctl
```

Запуск тестов:

```sh
go test ./...
```

## Сборка `.ipk`

Базовый пример:

```sh
ARCH_LIST="arm64:aarch64_cortex-a53 mipsle:mipsel_24kc" ./make.sh
```

Универсальный пакет:

```sh
ARCH_LIST="arm64:aarch64_cortex-a53 mipsle:mipsel_24kc mips:mips_24kc" UNIVERSAL_IPK=1 ./make.sh
```

Полезные переменные:

- `ARCH_LIST` — целевые архитектуры в формате `goarch[:opkg-arch]`.
- `DEFAULT_OPKG_ARCH` — архитектура opkg по умолчанию, если в `ARCH_LIST` не указан `:opkg-arch`.
- `INSTALL_PREFIX` — префикс установки внутри пакета, по умолчанию `/opt`.
- `PKG_VERSION` — строка версии пакета.
- `UNIVERSAL_IPK` — собрать дополнительный `*_all.ipk`.

Результат сборки:

- `build/*.ipk`
- `vpnerd`, `vpnerd-<goarch>`
- `vpnerhookcli`, `vpnerhookcli-<goarch>`

## Структура репозитория

| Путь | Назначение |
| --- | --- |
| `cmd/vpnerd` | Точка входа демона |
| `cmd/vpnerctl` | CLI администратора |
| `cmd/vpnerhookcli` | Hook helper |
| `internal/app` | Runtime/bootstrap |
| `internal/network` | Логика iptables/ipset/TPROXY |
| `internal/dns` | Встроенный DNS-сервер |
| `internal/doh` | DoH-резолвер |
| `internal/xray` | Управление Xray-конфигами и процессами |
| `internal/grpcserver` | gRPC handlers |
| `internal/config` | Загрузка YAML-конфига |
| `proto/` | Protobuf-описания |
| `make.sh` | Сборка `.ipk` |

## Диагностика

- `xray binary not found in PATH`: установите `xray-core` и проверьте, что `xray` виден в окружении демона.
- DNS не стартует на порту `53`: этот порт уже занят другим DNS-сервисом.
- `enable-tproxy: true` не работает на Keenetic: сначала проверьте компонент **Kernel modules for Netfilter** в KeeneticOS.
- `vpnerctl` не может подключиться к демону: проверьте, куда вы подключаетесь — в `/tmp/vpner.sock` или по TCP — и совпадает ли пароль с `grpc.auth.password`.
