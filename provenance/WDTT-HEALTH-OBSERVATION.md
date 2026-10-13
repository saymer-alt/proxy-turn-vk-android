# WDTT Health Monitor, этап 1: только наблюдение

Issue #16. Отдельная ветка поверх PR #15 (`dc78576bcc7593ad52b30334bd46670571753be1`),
который основан на PR #13. Эти ветки, клиент и транспорт не меняются.
Новая отдельная программа: `go_client/cmd/wdtt-health`.

Алгоритмический ориентир: последовательный sensor tick / consecutive failures /
новое подтверждение восстановления в [AWG Manager monitor.go](https://github.com/hoaxisr/awg-manager/blob/749e90187a85a9b06fd730bcf93d225c904043c0/internal/pingcheck/monitor.go).
Код управления AWG и его link toggle/backoff не копируется. Здесь вообще нет
API запуска/сигнализации WDTT, команд ip/awg, изменения маршрутов или watchdog.

## Поведение

| Состояние | Условие |
| --- | --- |
| STARTING | Пока нет подтверждённого нового ответа, менее трёх отказов |
| READY | Совпадает process identity/cwd, свежая телеметрия и новый ответ через SOCKS5 |
| DEGRADED | Три последовательных неудачных проверки; только recovery_suggested=true |
| STOPPED | Наблюдаемый процесс умер, стал zombie или изменил identity |
| TIME_LIMIT | Возраст исходного WDTT достиг 30 минут либо валиден его TIME_LIMIT marker |

Единичный/второй отказ после READY сохраняет состояние READY, но выводит
`consecutive_failures` и причину отказа; это не новый успешный check.
Одна следующая полноценная успешная проверка обнуляет счётчик и возвращает READY.
Счётчик насыщается на 3. Last-success не обновляется при отказе или отмене.
STOPPED/TIME_LIMIT терминальны для данного экземпляра монитора; замена PID
не подхватывается. TIME_LIMIT не рекомендует перезапуск. Отмена монитора не
объявляет работающий WDTT остановленным и никак не сигнализирует ему.

При attach владелец явно задаёт PID, абсолютный executable и private profile.
Проверяются `/proc/PID/stat` start ticks, точный `/proc/PID/exe` и inode,
`/proc/PID/cwd`. Возраст считается по `/proc/uptime` и AT_CLKTCK из auxv,
а не по предположению 100Hz или времени запуска монитора. Перезапуск монитора
не обновляет возраст WDTT. Исходный 30-минутный hard exit клиента не изменён.
Монитор прекращает свои проверки у этого предела, но не убивает процесс.

Входы — только bounded regular 0600 files текущего UID в каталогах 0700,
без symlink/hardlink. `socks-telemetry.json`: schema2, числовой uptime процесса,
mtime не раньше его старта, не из будущего и не старше 25 секунд. Статус READY
из файла не используется. TIME_LIMIT marker принимается только после старта
данного процесса. Перед публикацией результата процесс/телеметрия проверяются
снова. Listening socket 127.0.0.1:1081 дополнительно связывается с fd/inode
наблюдаемого PID через /proc; чужой SOCKS не может дать READY и не опрашивается.
Proxy1 / Keenetic интерфейсы вообще не читаются.

## Явная проверка передачи данных

Внешний target по умолчанию отсутствует. Требуется private `target_url`, явно
выбранный владельцем. Только HTTP/HTTPS GET через существующий фиксированный
SOCKS5 `127.0.0.1:1081`; CONNECT/удалённое разрешение имени выполняет SOCKS.
Нет direct fallback, env proxy, redirects, cookie jar, reuse/keepalive.
TLS проверяется штатным trust store, insecure TLS отсутствует.

Владелец должен подготовить endpoint, возвращающий:

- HTTP 2xx;
- `X-WDTT-Health-Nonce`, **равный nonce текущего запроса**;
- непустое тело до 4096 байт.

Монитор отправляет новый случайный 128-bit nonce на каждой проверке в таком же
заголовке и Cache-Control no-store/no-cache. Статический status, старый nonce,
HTTP redirect или просто успешный CONNECT не дают READY. URL без echo-protocol
заведомо не подходит, даже если обычный браузер открывает его.
Это доказательство новой HTTP-передачи через настроенный SOCKS, не UDP/всех сайтов.
HTTP разрешён для изолированного стенда; для удалённого endpoint предпочтителен
HTTPS с доверенным сертификатом. Наличие CA на Keenetic требует проверки владельцем.

Проверки последовательны, интервал после завершения 10..60 секунд (явный),
таймаут не более 8 секунд и остатка 30-минутной сессии. Нет фонового восстановления.
Вывод — JSON только с фиксированными состояниями/причинами и числовыми счётчиками/
временем, без URL/IP/headers/nonce/контента/credentials/raw errors. Core dumps
монитора отключаются. Он не пишет status или телеметрию WDTT.

## Будущее аппаратное испытание — только после отдельного допуска

Ничего из этого не запускалось агентом на Keenetic/VPS. Сборка монитора отдельно:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=readonly -trimpath -buildvcs=false -o wdtt-health ./cmd/wdtt-health
```

Для MIPSel используется GOARCH=mipsle и GOMIPS=softfloat, без изменения клиента.
Сначала проверить SHA, ABI и дополнительные RSS/CPU отдельно на разрешённом
стенде. KAS/Entware не устанавливают монитор; CI не публикует бинарники/releases.

Владелец стартует уже допущенную WDTT-сессию обычным ручным способом. Во время
её работы создаёт отдельный owner-only каталог и файл `health.json` (0700/0600)
через приватный редактор, без секретов в argv/history. Схема:

```json
{
  "pid": 1234,
  "executable": "/opt/wdtt-owner-lab/wt-client",
  "profile": "/opt/wdtt-owner-lab/private-profile",
  "target_url": "https://OWNER-CONSENTED-ENDPOINT/health",
  "interval_seconds": 10
}
```

Значения выше — только описание формата, не рабочие PID/endpoint/пути. Указать
фактические PID, exact executable и cwd WDTT; проверить их локально. Ни один
параметр не подставляется автоматически. Команда после заполнения:

```sh
/absolute/verified/wdtt-health -config-file /absolute/private-monitor/health.json
```

1. Проверить STARTING/READY, новые checked_at и отсутствие вывода private данных.
2. При отдельно разрешённом тесте недоступности **только тестового endpoint**
   дождаться трёх отказов и DEGRADED. Не менять рабочую маршрутизацию/Proxy1,
   не отключать Mihomo и не убивать WDTT для этого этапа.
3. Восстановить endpoint: новый nonce-ответ должен вернуть READY. Старый marker
   не должен помочь. Наблюдать ресурсы монитора и WDTT отдельно.
4. Дождаться штатного 30-минутного окончания: TIME_LIMIT, отсутствие автоматического
   нового процесса/трафика проверок. Не перезапускать сессию автоматически.
5. Ctrl-C останавливает только монитор. Диагностика DEGRADED означает ручную
   проверку ресурсов/логов/credentials владельцем; восстановление — отдельное
   действие владельца, отсутствующее в программе.

## Проверки и ограничения

Fake clock/state и net.Pipe SOCKS5+HTTP fixtures не выходят в интернет: success,
единичный сбой, три отказа, свежий recovery/отказ старого nonce, stale telemetry/
status, активный процесс при мёртвом SOCKS независимо от Proxy1, identity/PID
reuse, TIME_LIMIT без продления, отмена в dial/handshake и revalidation после
проверки. Запускаются все существующие short client tests и отдельный race check.
Существующий full candidate CI проверяет неизменные transport/Entware/KAS fixtures.

Нет аппаратной приёмки, memory-pressure policy, UDP-health, управления службой,
автоматического ремонта, атрибуции отказа конкретному TURN/WG worker. Программа
attach-only: умерший до запуска монитора процесс не считается достоверно
идентифицированным и даёт attach error, а не выдуманный READY/TIME_LIMIT.
При неизвестной process identity/freshness fail-closed после трёх проверок.
