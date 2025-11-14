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

1. OuterTLS открывается и остаётся активным всю сессию.
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

# TODO / Lab Plan

- [ ] Подготовить лабораторию `client → DPI → Go-proxy (HAProxy prototype) → nginx` в Docker Compose.
- [ ] Добавить контейнер DNS (CoreDNS/bind9) со своей зоной `example.internal`, TXT/HTTPS RR `oi-tls=1`, чтобы клиент узнавал о поддержке OI-TLS без утечки информации наружу (использовать DoH/DoT для скрытия от DPI).
- [ ] Реализовать микропровайдерскую сеть: отдельная bridge-сеть для клиента, ещё одна для Entry Node; DPI-контейнер dual-homed, проксирует/NAT-ит трафик и логирует TLS-пакеты (iptables + tcpdump/скрипт анализа хэндшейка).
- [ ] Реализовать простой DPI-контейнер (nginx/mitmproxy/собственный анализатор), который демонстрирует, что видит только OuterTLS даже при перехвате на уровне провайдера.
- [ ] Написать прототип прокси на Go (HAProxy-like) с поддержкой:
  - принятия OuterTLS без SNI и с IP-сертификатом,
  - извлечения InnerTLS ClientHello из первых application data,
  - маршрутизации к backend по реальному SNI.
- [ ] Настроить backend на `nginx` (TLS 1.3, несколько виртуальных хостов) для проверки прохождения InnerTLS без модификаций.
- [ ] Добавить клиентский контейнер (curl/openssl + скрипт) для демонстрации успешного рукопожатия и таймаутов.
- [ ] Задокументировать результаты (pcap, логи DPI, трассировки прокси) в формате, пригодном для черновика публикации IETF.
- [ ] (Лабораторно) Разрешить отключение проверки сертификатов на клиенте (`curl --insecure` / `tls.Config{InsecureSkipVerify:true}`) чтобы не поднимать свой CA, но явно отметить, что это только для теста — в продакшне OuterTLS/DoH должны валидироваться.

# Lab Architecture Description (draft)

### DNS Service
- Отдельный контейнер (CoreDNS/bind9) обслуживает внутреннюю зону `example.internal`.
- В зону добавляются TXT/HTTPS RR вида `_oitls.example.internal TXT "v=1"` и `example.internal HTTPS svcparam=oi-tls=1`.
- DNS контейнер экспортирует DoH/DoT на известный порт; клиент подключается напрямую и игнорирует внешние резолверы, чтобы провайдер (DPI) не видел сигнализацию.
- Сертификаты DNS (для DoH/DoT) хранятся в общем volume, чтобы клиент мог валидировать соединение.

### Networking / Micro-ISP Topology
- Создаются две docker-сети: `client_net` и `entry_net`. Клиент + DNS живут в `client_net`, Entry Node + backend в `entry_net`.
- DPI-контейнер имеет по одному интерфейсу в каждой сети и выступает как маршрутизатор/NAT (например, `iptables -t nat -A POSTROUTING -o entry_net -j MASQUERADE`).
- Статические маршруты/`default gateway` клиентов указывают на DPI-контейнер, чтобы весь трафик OuterTLS проходил через него.
- Для приближения к реальности DPI может применять shaping/filters, но в лаборатории достаточно логирования и опциональных ограничений по трафику.

### DPI Role
- DPI контейнер запускает `tcpdump`/`ngrep`/собственный Go/Python-анализатор и хранит сырой pcap (позже используется в отчёте).
- На старте DPI проверяет первые записи приложения и подтверждает, что видит только OuterTLS (ClientHello без SNI, ALPN и т.п.).
- Для демонстрации блокировок можно добавить режим «нарушения»: DPI дропает сессии, если обнаружен SNI, тем самым показывая преимущества OI-TLS.

### Client / Entry / Backend Flow
1. Клиент обращается к DNS по DoH/DoT, узнаёт TXT/HTTPS RR и понимает, что ресурс поддерживает OI-TLS.
2. Клиент устанавливает OuterTLS к Entry Node через DPI (последний записывает пакеты, но не видит SNI).
3. Внутри OuterTLS клиент отправляет InnerTLS ClientHello; Entry Node-«HAProxy» извлекает SNI и соединяется с backend.
4. Backend (`nginx` с несколькими server blocks) принимает InnerTLS как обычный TLS 1.3 handshake и обслуживает запрос.

### What to Document for IETF Draft
- Снимки pcap на уровне DPI, подтверждающие отсутствие SNI/ALPN/JA3.
- Логи DNS (с DoH/DoT) без утечки значений TXT наружу.
- Конфигурации сетей (описание `docker-compose.yml`, статические маршруты, iptables), чтобы показать реалистичность «микропровайдера».
- Ограничения: блокировка IP Entry Node полностью ломает схему; DNS без DoH/DoT раскрывает факт использования OI-TLS.
- В лаборатории допустимо временно отключить валидацию сертификатов клиента (для упрощения стенда), но обязательно описать риски MITM и подчеркнуть, что в реальной эксплуатации нужна собственная CA/выданный сертификат.

Не требует изменений в браузерах или TLS-стандарте, но для лаборатории нужно подчеркнуть:
- роль DNS (описание TXT/HTTPS RR, как клиент узнаёт о поддержке OI-TLS без раскрытия),
- поведение DPI в микропровайдерской топологии,
- ограничение возможностей DPI (OuterTLS как обычный TLS к IP).


# End of OI-TLS v1
