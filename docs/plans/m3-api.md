# M3 — доступ и API

Статус: план на согласовании (2026-11-03). Ветка `m3-api` от `master` (16113de).

**Цель:** права по методам и членство в `control_group` через Directory Services; урезанные ответы для остальных пользователей; полный контракт `status.get`; `tunnel.enable/disable`, пауза и `down -all`; снимок блокировки; `-json`, код выхода `3`, предупреждение о версиях; `docs/api.md`.

Правила — design 5, 9.1, 11, 12, 13, 14, 15, 21.1 (M3); CLAUDE.md.

## Контекст: состояние после M2

- `allow(uid)` = `uid == 0`, проверка в Echo-middleware: чужой uid получает HTTP 403 (`internal/rpc/server.go`). Design 14: отказ — ошибка JSON-RPC `5`, чтение доступно всем.
- Методы: `tunnel.setEnabled{name,enabled}`, `tunnel.disableAll`, `config.reload`, `status.get`, `diag.explain`, `diag.routes`. `daemon.pause/resume` нет.
- `control_group` разобран и проверен через `os/user.LookupGroup` (`internal/config/dir.go`); членство не проверяется.
- `state.json` (`internal/state`): только `tunnels`; `Save` не задаёт группу. Лог получает группу `control_group` после применения (`setLogGroup`).
- `rpc.Status`: нет `api_version`, `version`, `can_control`, `control_group`, `paused`, `config_dir`, `log_path`, `reason` у правила; `icon` без `paused` и без ошибки захвата DNS; `ConfigErrors` всегда полные.
- Битый конфиг при старте: `configured: false`, пустая таблица — `fallback: block` не держится (ограничение M2).
- CLI: все ошибки — код 1 (`main.go`); `-json` нет; `down -all` нет; HTTP 403 печатается как «run as root».

## Решения

1. **Права по методам** (design 5, 14). Middleware в `Serve` убирается: соединение принимается всегда, uid кладётся в контекст (`peerKey`). `status.get`, `diag.*` — всем; `config.reload`, `tunnel.*`, `daemon.*` — проверка `can_control(uid)` в обработчике; отказ — `jrpc.NewError(5, "permission denied", {control_group})`. Ошибка получения uid (`peer.err`): чтение — как «не управляет», изменение — код `5`.
2. **`can_control(uid)`** = uid 0, или uid владельца каталога конфига (`stat` при каждой проверке; нет каталога — только root), или член `control_group` применённого конфига. Конфиг не применён — только root и владелец. Логика — чистая, в `internal/rpc/access.go`: `Access{OwnerUID func() (uint32, bool), Group func() string, IsMember func(uid uint32, group string) (bool, error), Now func() time.Time}`, кэш членства по `(uid)` на 30 с (константа `membershipTTL`; смена группы в конфиге кэш сбрасывает). Ошибка `IsMember` — «не член», в кэш не кладётся, предупреждение в лог (раз на ошибку, без спама).
3. **`mbr_check_membership`** — cgo-файл `internal/rpc/membership_darwin.go`: `mbr_uid_to_uuid` и `mbr_identifier_to_uuid(ID_TYPE_GROUPNAME)` → `mbr_check_membership`. Числовой `control_group` — `ID_TYPE_GID` с `gid_t`. Группа не найдена (`ENOENT`) → «не член». Тонкий слой, без своей логики; юнит-тест — только на синтетических функциях, живой — VM. `config.LoadDir` остаётся на `os/user.LookupGroup` для проверки существования (в M2 принято; замена на Directory Services — по желанию, см. вопрос 3).
4. **Урезание** (design 5, «Видимость»): `Redact(Status, canControl)` и то же для `Explanation`, `Routes` — чистые функции в `internal/rpc/redact.go`. Для не управляющего: нет `endpoint`/`resolved` пиров, `check.addr`, `names` маршрутов, `config_errors` (вместо — `config_error_count`, он есть у всех), `servers` в `explain`. Остальное — см. вопрос 1.
5. **`status.get`** — поля из design 14: `api_version` (константа `1`), `version`, `can_control`, `control_group` (применённый конфиг; без конфига — пустая строка), `paused`, `config_dir`, `log_path`, `config_error_count`; `reason` у правила; `icon` с приоритетом design 14 (`paused`, ошибка захвата DNS — `warn`). `Enabled` у туннеля уже переключатель — сохраняется и на паузе (сейчас `Enabled = есть в d.tunnels`, на паузе станет ложью — берётся из переключателей, см. 8).
6. **`reason` правила** (чистая функция по `State`): правило в fallback или `Degraded` с `via` не пустым. Пауза → `paused`; иначе среди туннелей `via`, стоящих выше обслуживающего (в fallback — все): есть включённый переключателем, но `dead`/`error`/`starting`-сбой → `dead`; иначе (все выключены) → `disabled`.
7. **`tunnel.enable{name}` / `tunnel.disable{name}`** вместо `setEnabled`; результат `{"starts_on_resume": bool}` (true — на паузе включён, но ничего не поднято, design 12). Коды 2/3/4/5 — как в design 14. `tunnel.disableAll` — как есть, плюс право. `daemon.pause`, `daemon.resume` — идемпотентны, работают без конфига.
8. **Пауза** (design 12). `state.State.Paused bool` (`json:"paused,omitempty"`). `pause`: флаг в `state.json`, все туннели конфига опускаются (как `disableAll`, но переключатели не меняются), `reselect` → fallback, `sync`. `resume`: флаг снят, поднимается набор по переключателям и `autostart` (тот же расчёт, что `planApply`). На паузе `reload` и старт не поднимают туннели; `tunnel.enable/disable` меняют переключатель и `starts_on_resume`. Захват DNS не меняется. Для `status.get` `Enabled` = переключатель (переключатель/`autostart`, вычисляется в `rpc.State.Switches`), `State` — фактическое.
9. **Снимок блокировки** (design 9.1, 10.2, 11). `state.State.Block *Block{CIDRs, Domains []string}` (`json:"block,omitempty"`) — CIDR и домены сервисов правил `fallback: block` последнего удачно применённого конфига; ключей нет. Пишется при каждом удачном применении (если изменился). При старте с неудачным `LoadDir` демон строит из снимка синтетический `*config.Config` (один сервис, одно правило `block`, туннелей нет) и `RuleState{Fallback: true}`: таблица получает `reject`-маршруты, резолвер отвечает NODATA, захват DNS ставится (`NeedsDNS`). `configured` остаётся `false`, `cfg` для `status.get` — nil; снимок живёт в отдельном поле демона и в `tableFor`/`dns` подставляется только пока `cfg == nil`. Первое удачное применение его заменяет. Сначала — spike на `tableFor`/`dns.Choose` (см. «Факты spike»).
10. **Группа `state.json` и лога** — `control_group`: `State.Save(path, gid)`; `gid < 0` — группа не задаётся; chown временного файла до `rename`. Группа берётся из того же места, что для лога (`setLogGroup` → `setGroup`); до применения конфига — `admin`, как у лога (design 15). Лог `0640` уже есть.
11. **CLI.**
    - `status -json`, `explain -json`, `routes -json`, `check -json` — печатают структуры API (`check` — `rpc.ConfigErrorData`).
    - `down <tunnel> | -all`; `pause`, `resume`; `up` печатает «starts on resume» на паузе.
    - Коды выхода: `3` — демон недоступен (нет сокета, отказ, таймаут); ошибка `5` — код `1` и текст `permission denied: up/down/pause/resume/reload require root, the config owner or membership in group "<g>"` (при пустой группе — без хвоста про группу).
    - Предупреждение о версиях: `status` и `version` сравнивают `version` демона с версией CLI; расхождение — `warning: …` в stderr с `sudo brew services restart --sudo-service-user=root wgplex`, код не меняется. `wgplex version` печатает обе (демон недоступен — только CLI). Остальные команды лишнего вызова не делают (вопрос 2).
    - `status` показывает паузу, `reason` правил, `configured: false` отдельной строкой (замечание проверки M2).
12. **`docs/api.md`** (английский, с нуля): транспорт, права, ошибки `1–5`, все методы с параметрами и результатами, структуры, урезание, совместимость, `api_version`. Источник — design 5, 14 и код `internal/rpc`. Тот же текст — основа сообщения для `wgplex-app`.

## Не в M3

Точечный DNS и порт резолвера (M4), возврат (M5), формула и каталоги (M6); замена `LookupGroup` в `config` (вопрос 3). Лог пересоздаётся при удалении — нет (принято в M2).

## Сигнатуры

```go
// internal/rpc/rpc.go
const (
	APIVersion = 1
	CodeNoPermission = 5 // data: PermissionData
)
type PermissionData struct{ ControlGroup string `json:"control_group"` }
type EnableParams struct{ Name string `json:"name"` }     // tunnel.enable, tunnel.disable
type EnableResult struct{ StartsOnResume bool `json:"starts_on_resume,omitempty"` }
// Status: + APIVersion, Version, CanControl, ControlGroup, Paused, ConfigDir, LogPath, ConfigErrorCount
// RuleStatus: + Reason ("dead" | "disabled" | "paused")

// internal/rpc/access.go
const membershipTTL = 30 * time.Second
type Access struct{ /* OwnerUID, Group, IsMember, Now, cache under mutex */ }
func (a *Access) CanControl(uid uint32) bool
func (a *Access) Group() string

// internal/rpc/membership_darwin.go (cgo)
func IsMember(uid uint32, group string) (bool, error) // mbr_check_membership

// internal/rpc/redact.go
func RedactStatus(s Status) Status
func RedactExplanation(e Explanation) Explanation
func RedactRoutes(r Routes) Routes

// internal/rpc/state.go
// State: + Paused bool, Switches map[string]bool (effective toggle by tunnel), DNSError string
func ruleReason(...) string            // решение 6
// StatusOf(s *State) Status: icon по design 14; Version/CanControl/... добавляет Serve

// internal/rpc/server.go
type Daemon interface {
	Reload() (ApplyResult, error)
	Enable(name string) (EnableResult, error)
	Disable(name string) error
	DisableAll() error
	Pause() error
	Resume() error
	State() *State
}
func Serve(ctx, ln, d Daemon, acc *Access, meta Meta, log) error // Meta{Version, ConfigDir, LogPath}

// internal/state/state.go
type State struct {
	Tunnels map[string]bool `json:"tunnels,omitempty"`
	Paused  bool            `json:"paused,omitempty"`
	Block   *Block          `json:"block,omitempty"`
}
type Block struct{ CIDRs, Domains []string }
func (s State) Save(path string, gid int) error

// cmd/wgplex
// args: down -all; pause, resume; -json у status, explain, routes, check
// main/format: exit codes, printPermission, versionWarning(cli, daemon string) string
// daemon: Enable/Disable/Pause/Resume; blockConfig(*state.Block) (*config.Config, []router.RuleState)
```

## Файлы и зоны агентов

| Файл | Кто |
|---|---|
| `internal/state/state.go` | go-dev **A** |
| `internal/rpc/{access,membership_darwin,redact}.go`, `rpc.go`, `state.go`, `server.go` | go-dev **B** |
| `cmd/wgplex/{daemon,daemon_main,apply}.go` (пауза, снимок, группа, `Access`) | go-dev **C** (после A, B) |
| `cmd/wgplex/{args,main,format,client,check}.go` (CLI) | go-dev **D** (после B; параллельно C — файлы разные) |
| `internal/state/state_test.go`, `internal/rpc/{access,redact,state}_test.go`, `cmd/wgplex/{args,format,check,daemon_*}_test.go` | test-dev, по design, реализацию не читает |
| `docs/api.md` | go-dev **E** по design 14 и коду B (после B) |
| план, «Ход работы» | оркестратор |

## Шаги

1. План согласован; коммит плана.
2. **Spike** (оркестратор через `Explore`, без VM): как в `tableFor`/`dns.Choose` подставить снимок (решение 9); доступ к `peerKey` из обработчика `jrpc`; сборка cgo-файла под universal. Результат — в «Факты spike».
3. **`go-dev`, сигнатуры** одним коммитом (`panic("not implemented")`).
4. Параллельно, worktree'ы: go-dev **A**, **B**; test-dev по design.
5. Сведение, `make check`; расхождения тест/код решает `reviewer`.
6. go-dev **C** и **D** параллельно; затем **E** (`api.md`).
7. `reviewer` по `master...m3-api`: соответствие design, grep на остатки `setEnabled`, HTTP 403, ключи в ответах и логах, урезание не пропускает поля.
8. Проверка в VM (ниже), `general-purpose` на sonnet.
9. «Ход работы», текст для `wgplex-app`, слияние по CLAUDE.md.

## Проверка

**Unit** (дано/когда/то):

1. uid 0, владелец каталога, член группы → `CanControl`; чужой → нет; конфиг не применён → только root и владелец; каталога нет → только root.
2. Кэш: два вызова за 30 с — один `IsMember`; через 31 с — второй; смена группы в конфиге сбрасывает кэш; ошибка `IsMember` не кэшируется.
3. Мутирующий метод от чужого uid → ошибка `5` с `control_group`; чтение от него — результат; сбой `peer.err` — чтение да, изменение нет.
4. Redact: нет `endpoint`, `resolved`, `check.addr`, `names`, `servers`, текста `config_errors`, есть `config_error_count`; имена/состояния/`via`/текущий туннель/причина остались; у управляющего ответ полный.
5. `icon`: таблица приоритетов (нет конфига — `warn`; ошибка захвата DNS — `warn`; пауза — `paused`; ошибка конфига/`dead`/`error` — `warn`; `starting` и fallback из-за выключения не меняют; `up` — `on`; иначе `off`).
6. `reason`: пауза, все выключены → `disabled`, включённый мёртвый → `dead`, на резерве при мёртвом приоритетном → `dead`, смешанный случай.
7. `enabled` на паузе остаётся переключателем; `state` — `off`.
8. `state.json`: `paused` и `block` туда и обратно, старый файл без полей читается, `Save(gid)` — группа и `0640`, `gid < 0` — без chown.
9. Пауза: `pause` → туннели опущены, `reload` на паузе не поднимает, `enable` — `starts_on_resume`, `resume` поднимает по переключателям/`autostart`; перезапуск (загрузка `state.json`) с паузой — туннели не поднимаются.
10. Снимок: `blockConfig` → таблица из `reject` на CIDR, `dns.Choose` по домену снимка → `Block`; пустой снимок → ничего; удачное применение заменяет снимок; конфиг без `block` даёт пустой.
11. CLI: `down -all`, `pause`, `resume`, `-json` разбираются; недопустимые сочетания — usage (2); ошибка `5` → код 1 и текст; недоступный демон → код 3; `versionWarning` при расхождении.

**VM** (`general-purpose` на sonnet, `scripts/vm.sh`, клоны `wgp-check-m3-*`, `--net-bridged`; клоны и стенд сносятся после проверки). Стенд как в M2 (сервер WireGuard во второй VM, свежие ключи). Клиент: пользователи `admin` (владелец каталога конфига), `alice` (член `wgpctl`, группа внутри группы `wgpouter` — вложенность), `bob` (не член); `control_group: wgpctl`.

1. Матрица прав: root, `admin`-владелец, `alice`, `bob` — `status` (у `bob` нет endpoint, `config_error_count`), `up`/`down`/`pause`/`reload` (у `bob` код 1 с текстом о группе), сырой JSON-RPC через `curl --unix-socket` — ошибка `5`, не HTTP 403.
2. Членство: добавить `bob` в группу (`dseditgroup`) — управление появляется не позже чем через 30 с, без перезапуска; убрать — исчезает.
3. Вложенная группа: `alice` через `wgpouter` управляет.
4. Битый конфиг при старте: `kickstart -k` с испорченным YAML → `configured: false`, `reject`-маршрут на CIDR `block` (`netstat -rn`, флаг `2`), домен `block` → NODATA через `dig @127.0.0.1`, туннелей нет; `kill -9` → маршрут и ключ остаются; `reload` исправленного конфига — снимок заменён обычной работой.
5. Пауза: `pause` → туннель опущен, handshake сервера не растёт, правило в fallback с `reason: paused`, `block` держится, `up` — «starts on resume»; `kickstart -k` — пауза сохранилась; `resume` — туннель поднят. `down -all` → переключатели выключены, пережили перезапуск; новый туннель после `reload` — по `autostart`.
6. `icon` и `reason`: выключить туннель — правило `disabled`; остановить сервер — `dead`, `icon: warn`.
7. Файлы: `state.json` и лог — `0640`, группа `wgpctl` после `reload`; `bob` не читает лог.
8. CLI: код `3` при остановленной службе; бинарник другой версии (`-ldflags`) — предупреждение с командой перезапуска; `-json` у `status/explain/routes/check` разбирается `jq`.

Не проверяется: живой TCC; порт DNS занят (M4).

## Факты spike

Из чтения кода (2026-11-03):

- В `jrpc/v2` обработчик получает `*jrpc.Context` с полем `Echo *echo.Context`: из него берётся `Request().Context()` с `peerKey` — отдельного middleware для прав не нужно.
- `Serve` сейчас отвечает 403 из middleware; `client.go` и `printError` обрабатывают 403 как «run as root» — путь удаляется, но `httpError` остаётся для 413.
- `tableFor` и `dns.Choose` принимают `*config.Config` и `[]router.RuleState`; при `RuleState{Fallback:true}` и `Rule.Fallback == block` оба дают reject/NODATA независимо от `via` — синтетический конфиг (решение 9) подходит без правок роутера и резолвера.
- Все изменения конфигурации: `d.cfg == nil` — признак «не применён» в `toggle`, `DisableAll`, `snapshot`; снимок живёт отдельным полем.

Проверить в ходе работы (результат записать сюда):

- [x] cgo `mbr_*` (2026-11-03, хост, без root): собирается, `GOARCH=amd64` тоже. Имя группы — `ID_TYPE_GROUPNAME` (в SDK нет `ID_TYPE_GNAME`); несуществующая группа → код 2 (`ENOENT`) = «не член». Числовой `control_group` — `ID_TYPE_GID` с идентификатором `gid_t` (4 байта), а не строкой (строка → 22 `EINVAL`).
- [ ] В VM: universal-сборка `make build`, вызов из LaunchDaemon (root) и от обычного пользователя — как M0 G1, G5, G7.
- [x] `blockConfig` при `cfg == nil` (Explore): подстановка без правок не работает. Reject-маршруты строятся только по CIDR сервисов правила (`router/table.go:98-99`), NODATA — только по `Domains` (`dns/choose.go`): снимок хранит оба списка, синтетический сервис их получает. `startup` (`daemon.go:196-211`) при неудаче `apply` лишь делает `sync` и `releaseDNS`, захват DNS не ставит. Читатели `d.cfg`, которые должны видеть синтетику: `reselect` (`daemon.go:944,969`), `syncNow` (`:984`), `checkCapture` (`events.go:200`); остальные (`toggle`, `DisableAll`, `snapshot`, `planApply`, `health`) остаются на `d.cfg`, чтобы `configured: false` и «нет конфига» работали. Решение: метод `effectiveCfg()` (`d.cfg`, иначе синтетический из снимка) в трёх местах; в `startup` после неудачи — `reselect`, `sync`, `captureDNS` при `NeedsDNS`. `reselect` переписывает `d.rules` по `SelectRules`, поэтому у синтетического правила `via` — несуществующий туннель (тогда `Fallback: true`).
- [x] `ruleStatus` на паузе (Explore): правило с `via` без живых туннелей → `RuleState{Fallback:true}`, `Tunnel == ""`; `Degraded = len(via)>0 && Tunnel != via[0]` → true, `InFallback` true. Правило без `via` — не degraded.
- [x] `Enabled` сейчас = наличие записи в `d.tunnels` (`rpc/state.go:111-113`; `toggle` удаляет, `DisableAll` чистит). Для паузы `Enabled` берётся из `State.Switches` (переключатели из `state.json` и `autostart`), а не из `d.tunnels`; на паузе переключатели в `state.json` не затираются.

## Риски

- **Пауза затрагивает `Enabled`** (сейчас — наличие в `d.tunnels`): правка `snapshot`, `toggle`, `DisableAll`, `apply` — самая тяжёлая часть C; поэтому C одна и после A, B.
- **Снимок блокировки при `cfg == nil`**: места, читающие `d.cfg` напрямую (захват DNS, `tableFor`, `snapshot`), нужно перепроверить — spike шаг 2.
- **Смена контракта**: `tunnel.setEnabled` исчезает, `status.get` получает поля; `wgplex-app` ещё не начат (A1 — после M3), совместимости не нужно.
- **cgo в `internal/rpc`**: `go test` и `go vet` на darwin с cgo — работают; кросс-сборка amd64 — через `make build`, проверяется на шаге VM.
- **Урезание — риск утечки**: новые поля API в будущем по умолчанию видны всем; в `api.md` фиксируется список скрываемых полей, `reviewer` и тест сверяют.

## Вопросы пользователю

1. **Что ещё скрывать от не управляющих.** Design 5 перечисляет endpoint'ы, `check`, `names`, ошибки конфига. Неоднозначно: (а) `warnings` применённого конфига — там тексты с URL `check` и адресами; (б) `addresses` туннелей; (в) `servers`/`addrs` в `explain`; (г) handshake и трафик пиров. Рекомендация: скрыть (а) — заменить `warning_count`, и `servers` в `explain`; (б), (г) и `addrs` показывать (это состояние, не адреса пиров). Это уточнение design 5 — правка в той же ветке.
2. **Предупреждение о версиях** — только в `status` и `version`, без лишнего `status.get` перед каждой командой. Рекомендация: да; полное покрытие стоит второго вызова на каждую команду.
3. **`control_group` в `config.LoadDir`** оставить на `os/user.LookupGroup`, а не переписывать на `mbr_identifier_to_uuid` (design 5 говорит про Directory Services). Рекомендация: оставить — проверка существования и проверка членства сходятся на libc; расхождение записывается в design 5 одной фразой. Если нужна замена — одна функция, но cgo в `internal/config` ломает чистоту пакета.
4. **`control_group` в `status.get` без конфига** — пустая строка (рекомендация: управляют только root и владелец, группа не причём). Альтернатива — `admin`, как у группы лога.
5. **Результат `tunnel.enable`** — `{"starts_on_resume": true}` на паузе, иначе `{}`. Рекомендация: да (приложению нужна пометка, design 12).

## Ход работы

- [x] План согласован (2026-11-03): «да» на все пять рекомендаций; в design 5 внесено: урезание `warnings`→`warning_count`, `servers` в `explain`, `LookupGroup` для существования группы. В `status.get` добавляется `warning_count`; ветка включает master 4e7858a (раздел 17 → wgplex-app)
- [x] Spike (шаг 2): см. «Факты spike»; в VM остаётся universal и LaunchDaemon
- [ ] Сигнатуры
- [ ] Волна A/B/тесты
- [ ] C, D, E
- [ ] Ревью
- [ ] Проверка в VM
- [ ] Слияние
