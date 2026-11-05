# M4 — точечный DNS

Статус: план согласован, в работе. Ветка `m4-dns` от `master` (bab7b20).

**Цель:** вместо захвата всех имён (`SupplementalMatchDomains = [""]` на `127.0.0.1:53`, наследие Wirefork) — захват только зон конфига на нестандартном порту; запись и слежение через SystemConfiguration (cgo) вместо `scutil`; fail-closed при занятом порте.

Правила — design 4.1, 6, 8, 9.1, 18, 21.1 (M4); CLAUDE.md.

## Контекст: состояние после M3

- `dns.Capture/Release/Captured/SystemServers` (`internal/dns/sysdns_darwin.go`) гоняют `/usr/sbin/scutil` со скриптом на stdin; `captureScript` пишет один домен `""`, чтение — `parseScutil`.
- `netwatch.Watch` держит долгоживущий `scutil n.watch` с рестартом (`internal/netwatch/watch_darwin.go`).
- Резолвер слушает `dnsAddr = "127.0.0.1:53"` (`cmd/wgplex/daemon.go`); `srv.Start` не удался — демон выходит с кодом 1 (`daemon_main.go`), `KeepAlive` гоняет перезапуски.
- `Config.NeedsDNS()` — есть ли домены; зон как списка нет. Блок-снимок (M3) домены хранит.
- `dnsErr` → `icon: warn` в `status.get` уже есть (M3).

## Решения

1. **Порт** — константа `dnsPort = 5301` (вопрос 1). `ServerAddresses = [127.0.0.1]`, `ServerPort = 5301`; резолвер слушает `127.0.0.1:5301`.
2. **Зоны** — `Config.Zones() []string` (чистая, `internal/config`): имена доменов сервисов из правил (`=example.com` и `example.com` дают зону `example.com`) и `dns_domains` туннелей; нижний регистр, без точки, без дублей, отсортированы. Зон нет → ключ не ставится (как `NeedsDNS` сейчас; `NeedsDNS` = `len(Zones()) > 0`). Для блок-снимка (M3) зоны считаются из его синтетического конфига.
3. **Лимит 1000 зон** — ошибка валидации конфига (`config.LoadDir`, текст с числом зон), `wgplex check` её показывает. Не применённый из-за лимита конфиг ведёт себя как битый (старт — блок-снимок, reload — прежний конфиг).
4. **Запись ключа через SC** (cgo, `internal/dns/sc_darwin.go`): `SCDynamicStoreCreate`, `SCDynamicStoreSetValue` / `RemoveValue` / `CopyValue`. Поля: `ServerAddresses`, `ServerPort`, `SupplementalMatchDomains` (зоны), `SupplementalMatchOrders` (по `1` на зону), `SupplementalMatchDomainsNoSearch = 1`. Чтение (`SystemServers`, `Captured`, проверка после записи) — через тот же слой; `scutil` из кода уходит целиком, `parseScutil` и `captureScript` удаляются, чистый `systemServers(setup, state map[string][]string)` остаётся (словарь CF → `map[string][]string` в тонком слое). Сброс кэша — как сейчас (`dscacheutil -flushcache`, `killall -HUP mDNSResponder`).
5. **Запись только при изменении зон** (сравнение с последним записанным набором и фактическим ключом): reload без смены зон не пишет и не сбрасывает кэш. Пауза, «Выключить все» и состояние туннелей зоны не меняют (design 8).
6. **Проверка `scutil --dns`** (design 8): после записи `scutil --dns` разбирается чистым парсером (`internal/dns/scutildns.go`: блоки `resolver #N`, поля `domain`, `nameserver[0]`, `port`); нужны блоки, где все зоны ключа указывают на `127.0.0.1` с портом `dnsPort`. Не нашлось — ошибка в `dnsErr` (`icon: warn`) и лог. `scutil --dns` — единственное оставшееся использование `scutil`, только чтение вывода.
7. **Слежение через SC** (`internal/netwatch/watch_darwin.go` на cgo): сессия `SCDynamicStoreCreate` с callback'ом, `SCDynamicStoreSetNotificationKeys` (те же ключи и паттерны, что сейчас в `networkKeys`/`networkPatterns`, плюс ключ захвата), `CFRunLoop` в горутине с `runtime.LockOSThread`; callback (`//export`) кладёт события в `raw`. Остальное (`Wake`, `Resync` раз в 30 с, дебаунс) — как есть. Рестарт `scutil` с бэкоффом уходит; рестарт `configd` (сессия мертва) — пересоздание сессии и `Resync`.
8. **Порт занят — fail-closed** (design 8). `srv.Start` не удался → демон не выходит: ошибка в `dnsErr` и лог, зоны публикуются всё равно, повтор `Start` раз в 60 с (константа `dnsRetry`) и при `config.reload`. Успех → `dnsErr` сбрасывается. Резолвер без сокета не отвечает (NODATA/SERVFAIL не нужны — порт молчит). `SO_REUSEPORT` не выставляется: занятость порта — сигнал, а не помеха.
9. **Старт до конфига.** Резолвер должен слушать до записи ключа (как сейчас); при занятом порте ключ всё равно пишется (зоны есть), иначе при `KeepAlive`-перезапуске `block` разорвётся (9.1, 4.1).
10. **`SupplementalMatchOrders`** — design: «меньшее значение выигрывает» не проверено. Проверка в VM (шаг spike): чужой сервис с теми же зонами и порядком `2` и `0`; выигрывает ли wgplex с `1`. Если выигрывает больший — значение меняется на `0` (или пишется порядок, который побеждает всегда) и правится design 8.

## Не в M4

Возврат на приоритетный туннель (M5), формула и поставка (M6). Изменений `api.md` нет (поведение `dnsErr` и `icon` уже в контракте); если проверка VM покажет новую причину ошибки — только текст.

## Сигнатуры

```go
// internal/config
func (c *Config) Zones() []string // sorted, deduped, lowercase; NeedsDNS = len > 0
const MaxZones = 1000             // LoadDir: error above

// internal/dns
const Port = 5301
func Capture(zones []string) error // SCDynamicStoreSetValue + read back + flush (ErrFlush)
func Release() error
func Captured() (zones []string, ok bool, err error) // current zones of the key
func SystemServers() ([]netip.Addr, error)
func VerifyZones(zones []string) error               // scutil --dns, parseScutilDNS
func parseScutilDNS(out string) []resolverBlock      // pure

// internal/netwatch
func Watch(ctx context.Context, captureKey string, log *slog.Logger) <-chan Event // signature as before, SC inside
```

## Задачи и порядок

1. **Сигнатуры** (`go-dev`): типы и функции без логики; тесты компилируются.
2. **Параллельно** (файлы не пересекаются):
   - A (`go-dev`, worktree): `internal/dns` — `sc_darwin.go`, `Capture/Release/Captured/SystemServers`, `VerifyZones`, `parseScutilDNS`; удаление `scutil()`.
   - B (`go-dev`, worktree): `internal/netwatch/watch_darwin.go` на SC.
   - C (`go-dev`, worktree): `internal/config` — `Zones`, `MaxZones`, валидация; `NeedsDNS`.
   - T (`test-dev`): `Zones` и лимит, `parseScutilDNS`, `systemServers`, повтор раз в 60 с (на фейковых часах) — по design, не глядя в реализацию.
3. **Демон** (`go-dev`, после 2): `cmd/wgplex` — `dnsPort`, зоны в `captureDNS`, запись только при изменении, повтор `Start`, `dnsErr`, проверка после записи, `checkCapture` по зонам, блок-снимок.
4. **Ревью** (`reviewer`), исправления.
5. **Проверка в VM** (`general-purpose`, sonnet, bridged, `scripts/vm.sh`): порядок `SupplementalMatchOrders` (п. 10); имена из правил и вне них; рядом с dnsmasq на `:53`; порт `5301` занят — имена из правил не резолвятся, `icon: warn`, после освобождения (≤60 с) — резолвятся; 1000 зон проходят, 1001 — ошибка; перезапуск `configd` (`killall configd`) — ключ и слежение восстановлены; перезапуск демона не рвёт `block`.
6. **Документы:** design 8 по итогам п. 10; «Ход работы»; слияние по условиям CLAUDE.md.

## Вопросы к пользователю

1. Порт резолвера: `5301`? (Рекомендация: да; `5353` — mDNS, `5354` — Bonjour.)
2. Убрать `scutil` из кода целиком (кроме разбора `scutil --dns`), включая чтение ключей? (Рекомендация: да — один слой SC вместо двух, `parseScutil` удаляется.)
3. Лимит 1000 зон — ошибка валидации (применение конфига отклоняется), как в design? (Рекомендация: да.)
4. Ключ `ServerPort` пишется и при занятом порте (зоны публикуются, имена не резолвятся) — как в design 8, подтвердить.

## Ход работы

- [x] План согласован (2026-11-05): «да» на все четыре рекомендации
- [x] Сигнатуры (6f57d07); волна A/B/C/тесты (bcaf6c9, 5434b0c, 2ada3cf, 273fd71); демон (c3e9c7a)
- [x] Ревью (reviewer, opus): блокеров нет. Исправлено (eb56627): loopback в системных DNS не отбрасывается (резолвер на :5301, петли нет); код SCError читается в том же C-вызове; падение резолвера в работе — повтор listen, ключ остаётся (9.1); тест решения 9; комментарии. Решение пользователя (2026-11-05): ошибки «порт занят» и «scutil --dns» — текстом в `warnings` status.get (6515a7a, `api.md`: Icon и warnings). Принято: образец `scutil --dns` в тесте написан вручную — сверить в VM; netwatch читает SCError на закреплённом потоке; поведение после `killall configd` — в VM.
- [ ] Проверка в VM
