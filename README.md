# OI-TLS (Outer-Inner TLS) — Specification v1

## Overview

OI-TLS (Outer-Inner TLS) — протокол, позволяющий скрывать параметры TLS-рукопожатия
(ClientHello, SNI, ALPN, cipher list, JA3 fingerprint) от DPI и промежуточных сетевых устройств.
Это достигается разделением соединения на два уровня:

1) **OuterTLS** — внешний TLS 1.3 канал, устанавливаемый к IP-адресу точки входа.
2) **InnerTLS** — обычный TLS 1.3 handshake, инкапсулируемый внутрь OuterTLS
   как зашифрованные application data.

DPI видит только OuterTLS к IP, который неотличим от стандартного HTTPS.
InnerTLS скрыт полностью.


## Goals

- Скрытие SNI и структуры ClientHello от DPI.
- Совместимость с существующими балансировщиками (HAProxy, nginx).
- Использование стандартного TLS 1.3 без модификации формата.
- Никаких новых TLS-расширений или нестандартных полей.
- Маскировка соединения под обычный HTTPS.
- Простота интеграции на стороне инфраструктуры.


## Threat Model

OI-TLS защищает от:
- DPI-анализаторов на маршруте.
- Блокировок по SNI.
- Фильтрации по JA3/ClientHello fingerprint.
- Анализа ALPN.

OI-TLS не защищает от:
- жёсткого IP-бана точки входа,
- атак на DNS без DoH/DoT,
- блокировок по географии или ASN.


## Architecture

```
Client
│
│ OuterTLS (TLS 1.3 → IP only)
▼
Entry Node (HAProxy/nginx + OI-TLS module)
│
│ InnerTLS (TLS 1.3 → backend)
▼
Backend Server
```


- **Client** — инициирует OuterTLS, затем отправляет InnerTLS внутри него.
- **Entry Node** — принимает OuterTLS, извлекает InnerTLS ClientHello, определяет SNI и маршрутизирует.
- **Backend** — получает обычное TLS-подключение.


## OuterTLS Establishment

1. Клиент делает DNS-запрос:
example.com → 203.0.113.10

2. Клиент открывает TCP:
connect(203.0.113.10:443)


3. Клиент выполняет **обычный TLS 1.3 handshake** к IP-адресу:
- SNI **отсутствует полностью**.
- Используются стандартные cipher suites.
- Нет нестандартных extensions.
- Сертификат сервера содержит IP в SAN:
  ```
  X509v3 Subject Alternative Name:
      IP Address:203.0.113.10
  ```

OuterTLS неотличим от обычного HTTPS-подключения «к IP».


## InnerTLS Injection

После завершения OuterTLS клиент:

1. Генерирует стандартный **InnerTLS ClientHello**.
2. Отправляет его в виде TLS application data внутри OuterTLS.

Entry Node:
- получает InnerTLS ClientHello,
- извлекает SNI,
- определяет backend,
- открывает TCP-соединение к backend,
- передаёт InnerTLS туда.


## Backend TLS

Backend получает InnerTLS ClientHello как обычный входящий TLS handshake.

Он:
- завершает TLS 1.3 установку,
- работает как обычный HTTPS/HTTP2/WebSocket сервер.


## Session Flow (base version)

1. OuterTLS открывается и остаётся активным всю сессию (в базовой версии; далее можно вводить ограниченный TTL и «схлопывание» OuterTLS после старта InnerTLS).
2. InnerTLS-протокол полностью проксируется через OuterTLS.
3. Клиент и backend общаются через Entry Node без модификаций.
4. DPI видит только OuterTLS → обычный HTTPS к IP.


## Error Handling

Entry Node закрывает OuterTLS если:
- InnerTLS ClientHello не получен в течение N секунд (рекомендуется 10s),
- получен мусор вместо ClientHello,
- превышен лимит данных до InnerTLS (например 64 KB),
- backend недоступен или TLS не завершился.

Клиент должен воспринимать это как обычное TLS-ошибку.


## DNS Discovery (optional)

Поддержка OI-TLS может сигнализироваться через DNS:

TXT:
_oitls.example.com TXT "v=1"

HTTPS RR:
example.com HTTPS svcparam=oi-tls=1

Эти записи позволяют клиенту заранее понять, поддерживается ли OI-TLS на целевом сервисе. Это убирает бессмысленные попытки построить OuterTLS к узлу, который его не понимает (что могло бы раскрыть сам факт использования протокола), и позволяет переключиться на обычный TLS при отсутствии сигнала.

При использовании DoH/DoT DPI не видит этих записей.


## Security Properties

- OuterTLS выглядит как стандартный TLS 1.3 handshake к IP.
- Без SNI в ClientHello.
- Без нестандартных расширений.
- DPI не может отличить OuterTLS от обычного HTTPS-вызова к IP.
- InnerTLS полностью скрывает:
  - настоящий SNI,
  - расширения ClientHello,
  - ALPN,
  - JA3 fingerprint,
  - cipher list.


## Implementation Requirements

### Client:
- поддержка TLS 1.3,
- отправка InnerTLS ClientHello через application data OuterTLS,
- работа через прозрачный InnerTLS-туннель.

### Entry Node:
- парсинг первых application data,
- извлечение InnerTLS ClientHello,
- маршрутизация по SNI,
- проксирование InnerTLS.

### Backend:
- стандартный TLS 1.3 сервер.


## Compatibility

Совместимо с:
- TLS 1.3,
- TLS 1.2 (Inner),
- HTTP/1.1, HTTP/2,
- WebSocket,
- любой backend-инфраструктурой.

## Baseline Lab Implementation (no OI-TLS yet)

Артефакты расположены в `lab/baseline/`:
- `docker-compose.yml` — описывает четыре контейнера: `client` (alpine+curl), `dpi` (Dual NIC router с tcpdump), `haproxy` (официальный образ) и `backend` (nginx с `/healthz`).
- `backend/nginx.conf` — отвечает `200 OK` на `/healthz`, используется как целевой сервис.
- `backend/certs/` — self-signed сертификат (`backend.local`) и ключ; nginx слушает `8443/tcp` c TLS 1.2/1.3.
- `haproxy/haproxy.cfg` — TCP frontend на `443`, который без модификаций пересылает трафик на backend (`172.31.0.20:8443`) и проверяет порт через `tcp-check`.
- `dpi/` — Dockerfile и entrypoint, которые включают IP forwarding, NAT и пишут pcap в `lab/baseline/dpi/captures/dpi-baseline.pcap` (entrypoint сам определяет интерфейсы по IP `172.30.0.254/172.31.0.254`; tcpdump слушает клиентский iface и фильтрует `host 172.30.0.10 and host 172.31.0.10`, т.е. только трафик client ↔ HAProxy).
- `dpi/export_pcap.sh` — скрипт, который из того же pcap генерирует читаемый TLS/HTTP дамп (`dpi-baseline.pcap.txt`) и короткое SNI-summary (`dpi-baseline.pcap.sni.txt`), используя `tshark` и образ `nicolaka/netshoot`.
- `dns/` — CoreDNS конфигурация, отдаёт `haproxy.example.internal` → `172.31.0.10`, `backend.example.internal` → `172.31.0.10`.
- `client/` — Dockerfile, `health_check.sh` и утилита `clientctl` (`clientctl request` вызывает скрипт), которые переназначают default gateway на DPI, используют CoreDNS (resolv.conf) и делают `curl --insecure --resolve haproxy.example.internal:443:172.31.0.10` (SNI `haproxy.example.internal`).

### Как запустить стенд

```bash
cd OI-TLS/lab/baseline
docker compose up -d backend haproxy dpi
docker compose up -d dns client   # DNS нужен до клиента
# Отправить запрос можно так:
docker compose exec client clientctl request
# После теста можно экспортировать pcap в текст + SNI summary:
cd lab/baseline/dpi && ./export_pcap.sh   # создаст captures/dpi-baseline.pcap.{txt,sni.txt}
```

После выполнения:
- ответ `OK` подтверждает, что baseline маршрут рабочий; скрипт вызывает `curl --insecure --resolve haproxy.example.internal:443:172.31.0.10 https://haproxy.example.internal/healthz` (DNS выдаёт тот же IP), поэтому ClientHello содержит SNI `haproxy.example.internal`, что фиксируется DPI (чтобы далее сравнить с OI-TLS),
- pcap-файл сохраняется в `lab/baseline/dpi/captures/dpi-baseline.pcap`, DPI видит обычный HTTP/TLS (без OI-TLS);
- DPI контейнер требует `NET_ADMIN`, `NET_RAW`, `sysctl net.ipv4.ip_forward=1`; entrypoint сам находит нужные интерфейсы по локальным IP (`172.30.0.254` и `172.31.0.254`), поэтому порядок сетей в Docker не важен. Клиенту также нужен `NET_ADMIN`, чтобы менять default gateway. Утилита `clientctl request` запускает запрос /healthz через DPI.
- для остановки: `docker compose down -v`.
- Лабораторный режим допускает использование обычных UDP-запросов к CoreDNS и отключённую проверку TLS-сертификатов (`curl --insecure`); в реальной OI-TLS реализации оба компонента обязаны работать через DoH/DoT + строгую валидацию сертификатов, чтобы DPI не мог увидеть сигнализацию или выполнить MITM.

Этот стенд используется как контрольный: далее будет добавлен параллельный Compose/сервисы для варианта с OI-TLS, при этом DPI и backend сохранятся, а клиентская часть будет заменена на реализацию, отправляющую OuterTLS/InnerTLS (потребуется собственный клиент).

### Результаты baseline теста
- Трафик `client → DPI → HAProxy → nginx` успешно воспроизводится с `clientctl request`.
- В `lab/baseline/dpi/captures/dpi-baseline.pcap` и `dpi-baseline.pcap.sni.txt` DPI фиксирует открытый SNI `haproxy.example.internal`, так как это обычный TLS без OI-TLS инкапсуляции.
- Итог подтверждает ожидаемое: провайдерский DPI, наблюдающий канал между клиентом и точкой входа, видит ClientHello/SNI и все расширения TLS.

## OI-TLS Lab Implementation

Новый стенд находится в `lab/oi-tls/` и повторяет реальный протокол:
- `entry/` — Go-прокси (замена HAProxy). Принимает OuterTLS на `:443`, извлекает InnerTLS ClientHello, определяет SNI и проксирует поток на backend (`172.41.0.20:8443`). Сертификат `entry/certs/` self-signed, OuterTLS идёт к IP без SNI.
- `client/` — Go-клиент `clientctl`, который:
  - делает DNS-запрос `_oitls.example.internal TXT` через CoreDNS по UDP (в реальности нужен DoH/DoT),
  - устанавливает OuterTLS к Entry Node без верификации сертификата (лаборатория) и без SNI,
  - внутри OuterTLS запускает обычный TLS-клиент к `backend.example.internal`, выполняет `GET /healthz`.
- `dns/` — CoreDNS зона `example.internal` (entry/backend, TXT `v=1`); в тестах работает по UDP, но README подчёркивает, что в реальной интеграции потребуется DoH/DoT + валидация сертификатов.
- `dpi/` — тот же контейнер, что в baseline (build context `../baseline/dpi`), пишет `lab/oi-tls/dpi/captures/oi-tls.pcap` — в нём DPI видит только OuterTLS к IP без SNI/ALPN.
- `backend/` — переиспользует baseline nginx конфиг/сертификаты (`../baseline/backend`).

### Как запустить OI-TLS стенд

```bash
cd OI-TLS/lab/oi-tls
docker compose up -d backend entry dns dpi
docker compose up -d client
# Запустить запрос:
docker compose exec client clientctl
# Экспорт OuterTLS трафика (SNI скрыт):
cd OI-TLS/lab/oi-tls/dpi && ./export_pcap.sh   # создаст captures/oi-tls.pcap{,.txt,.sni.txt}
```

- Клиент логирует TXT-рекорд, завершает Outer/Inner TLS и печатает ответ backend.
- DPI pcap показывает, что между клиентом и Entry Node идёт обычный TLS к IP без SNI; файл `.sni.txt` будет пустым — InnerTLS скрыт внутри OuterTLS и виден только Entry Node.
- Как и в baseline, лаборатория отключает верификацию сертификатов и использует UDP DNS; в реальной OI-TLS интеграции нужно DoH/DoT + собственная CA/валидные сертификаты.

- Снятые `oi-tls.pcap` и `oi-tls.pcap.sni.txt` показали, что DPI видит только OuterTLS (без SNI/ALPN), а Entry Node логирует InnerTLS SNI `backend.example.internal`.

> Лабораторные стенды служат демонстрацией логики OI-TLS и анализа трафика. Это не готовые библиотеки/SDK; для продакшн-внедрения нужна собственная реализация клиента и entry node с учётом требований из раздела Production Notes.

## Lab Setup Guide

### Prerequisites
- Docker + Docker Compose v2;
- Git для клонирования репозитория;
- Опционально `xml2rfc`, если нужно пересобрать Internet-Draft.

### Клонирование репозитория
```bash
git clone https://github.com/EvrkMs/OI-TLS.git
cd OI-TLS
```

### Baseline Lab
```bash
cd lab/baseline
docker compose up -d backend haproxy dpi dns client
docker compose exec client clientctl request
cd dpi && ./export_pcap.sh   # создаст captures/dpi-baseline.pcap{,.txt,.sni.txt}
docker compose down -v
```

### OI-TLS Lab
```bash
cd lab/oi-tls
docker compose up -d backend entry dns dpi client
docker compose exec client clientctl
cd dpi && ./export_pcap.sh   # создаст captures/oi-tls.pcap{,.txt,.sni.txt}
docker compose down -v
```

### Пересборка Internet-Draft (опционально)
```bash
docker run --rm -v "$PWD":/work -w /work python:3.11 \
  sh -c "pip install xml2rfc >/dev/null && xml2rfc draft-filimonov-oitls-00.xml --text --out draft-filimonov-oitls-00.txt"
```

## Production Notes
- В финальной реализации DNS-запросы и сигнализация поддержки OI-TLS должны идти через DoH/DoT с полной проверкой сертификатов, чтобы скрыть TXT/HTTPS RR и исключить MITM.
- После завершения InnerTLS Entry Node может сбрасывать OuterTLS (или переиспользовать его очень короткое время), чтобы шифрование на входной точке прекращалось и SNI более не «светился» в outer-канале.
- OuterTLS соединения должны иметь управляемый TTL (значение можно публиковать вместе с `_oitls` TXT/HTTPS RR или отдельным параметром) и возможность переподключения/переиспользования. Entry Node автоматически сбрасывает OuterTLS, если InnerTLS не стартовал в пределах этого окна, предотвращая массовое создание «пустых» туннелей и CPU-DDoS на шифрование.

# End of OI-TLS v1
