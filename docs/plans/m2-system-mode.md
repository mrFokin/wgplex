# M2 — системный режим

Статус: план на согласовании (2026-11-03). Ветка `m2-system-mode` от `master` (2132c9b).

**Цель:** демон работает как системная служба (design 4.1): сам читает каталог конфига с проверкой прав, помнит переключатели туннелей в `state.json`, стартует с битым конфигом, пишет лог с ротацией, стартует без предварительной уборки. CLI получает `wgplex check`; `config.apply` заменяется на `config.reload`; `wgplex.yaml` принимает `control_group`.

Правила — design 4.1, 5, 6, 7.2, 8, 10, 11, 13, 15, 21.1 (M2); CLAUDE.md. Структура плана взята из черновика ветки opencode-archive; содержание сверено с `design.md` и кодом `master`.

## Контекст: состояние после M1

- Конфиг доставляет клиент: `wgplex reload [-config dir]` читает каталог и шлёт файлы в `config.apply` (`cmd/wgplex/configdir.go`, `internal/rpc/rpc.go`: `ApplyParams`, `Daemon.Apply`).
- `planApply(cur, next, enabled, running)` (`cmd/wgplex/apply.go`): при повторном применении переключатели берутся из памяти (`enabled`), а не из `autostart`. Design 10.2 требует другого: туннель без записи в `state.json` следует `autostart` при **каждом** удачном применении (правка `autostart` действует с ближайшего `reload`).
- Старт (`cmd/wgplex/daemon_main.go:68-72`): `router.DeleteOwned()` и `releaseDNS()` — предварительная уборка. Первая синхронизация таблицы (`syncNow`) случается только внутри `Apply`; при старте без конфига её нет.
- `Sync` и так снимает наши host-route'ы, которых нет в таблице (`internal/router/sync_darwin.go`: «keep comes from t alone»), а демон добавляет в таблицу только `d.hosts` — после рестарта пустой. Значит осиротевшие host-route'ы уйдут первой синхронизацией (решение пользователя 2026-11-02 по вопросу 1 задачи Д M1, design 7.2) — **при условии, что она состоится даже без конфига**.
- `d.captured` (ключ DNS) в `Apply` при конфиге без доменов гасит `releaseDNS` только если `captured == true`; после рестарта он `false`, чужой ключ прошлой сессии остался бы.
- Логи — только stderr. Флаги `daemon`: `-v`, `-socket`. `allow` = `uid == 0` (права по методам — M3).
- DNS как в Wirefork до M4: `127.0.0.1:53`, `[""]` через `scutil`.

## Решения

1. **Демон читает каталог сам** (design 5, 10.2): `config.LoadDir(dir)` — права и владельцы, читаются только `wgplex.yaml` и `.conf`, на которые ссылаются туннели; остальные `*.yaml` — предупреждение «ignored»; все ошибки собираются (в том числе ошибки прав каждого файла). Файл, не прошедший проверку прав, всё равно передаётся в `Load`, чтобы собрать остальные ошибки; конфиг в любом случае отвергается. Не читается (oversize, не обычный файл, ошибка открытия) — только ошибка.
2. **Владелец каталога** — `stat` каталога при каждой проверке (`syscall.Stat_t.Uid`). Допустимые владельцы файла: root или владелец каталога; `mode & 0o022 != 0` — ошибка (после разрешения симлинка — `os.Stat`); предки каталога не проверяются. `.conf` с `mode & 0o044 != 0` — предупреждение. Каталога нет — ошибка «config directory … not found»; каталог пуст, `wgplex.yaml` нет — «wgplex.yaml not found» (как в `Load`).
3. **TCC:** `EPERM` при открытии/чтении (`errors.Is(err, fs.ErrPermission)` + `syscall.EPERM`) — текст называет TCC и советует положить файл в каталог конфига. Живой TCC не проверяется (VM-сценария нет, unit — на синтетической ошибке).
4. **`control_group`:** `Config.ControlGroup string`, по умолчанию `admin`. Существование — `os/user.LookupGroup` в `LoadDir` (переменная пакета `lookupGroup` для подмены в тестах); `user.UnknownGroupError` — ошибка конфига; числовой gid принимается без проверки (design 5). Собственно проверки членства, кэша и `mbr_check_membership` нет — это M3; на M2 поле только принимается и валидируется, права по методам прежние (`uid == 0`). **Отклонение для согласования:** design 5 описывает поиск через Directory Services (cgo) — на M2 берём `os/user` (на darwin с cgo это тот же `getgrnam_r`); в M3 при cgo-реализации членства заменяется одним вызовом.
5. **`state.json`** (design 11): `{"tunnels":{"nl":true,"home":false}}` — только явные действия (`tunnel.setEnabled`, `tunnel.disableAll`); без записи — `autostart`. Запись атомарная (tmp в том же каталоге + `rename`), `0640`. Битый/нечитаемый файл — предупреждение в лог, пустое состояние. Каждое удачное применение (старт и `reload`) убирает записи туннелей, которых нет в конфиге, и сохраняет файл, если что-то убрано. Пауза (`paused`) и снимок блокировки (`block`) — M3; формат расширяется добавлением полей. Нет каталога `var/wgplex` — ошибка записи в лог и `status.get`-предупреждение, демон работает (design 4.1: каталоги создаёт формула; демон создаёт только недостающее **внутри**).
6. **`planApply` по design 10.2:** `planApply(cur, next, switches, running)` — `switches` вместо `enabled`: `on = switches[name]` если запись есть, иначе `autostart`; `cur == nil` больше не особый случай для выбора (только для `stop`/`restart`). `nextEnabled` — как раньше.
7. **`tunnel.setEnabled` / `tunnel.disableAll`** пишут в `state.json` (disableAll — `false` всем туннелям текущего конфига). Имена методов остаются (`tunnel.enable`/`disable` — M3). `tunnel.*` при `configured == false` — код `2`, включая `disableAll` (design 14; в M1 `disableAll` без конфига возвращал успех — исправить).
8. **Старт с битым конфигом** (design 4.1, 10.2): ошибка `LoadDir` при старте — `cfgErrs` заполнены, `configured: false`, демон жив; сразу выполняется синхронизация пустого состояния (маршруты прошлого запуска уходят, ключ DNS снимается). Снимка блокировки нет (M3) — до M3 `fallback: block` при битом конфиге на старте не держится; записывается в «Ход работы» как известное ограничение этапа.
9. **`config.reload`** — без параметров, права прежние (root). Результат — `ApplyResult` как у `config.apply`. Ошибка валидации — код `1`, работает прежний конфиг, `config_errors` обновляются. `ApplyParams` и `config.apply` удаляются. `wgplex reload` — только триггер: `-config` у него убирается (клиентская команда не знает каталога демона).
10. **Старт без предварительной уборки:** `DeleteOwned` и `releaseDNS` из старта убираются; `DeleteOwned` удаляется (мёртвый код). Первая синхронизация — при старте (решение 8) или в первом `Apply`. Ключ DNS: `Apply` без доменов в конфиге вызывает `releaseDNS` всегда (не только при `captured`) — идемпотентно, снимает и ключ прошлого запуска; с доменами — `captureDNS` переиздаёт ключ (как сейчас). Остановка (`shutdown`) уже снимает ключ безусловно.
11. **Логи** (design 15): `<prefix>/var/log/wgplex/wgplex.log`, `cmd/wgplex/logfile.go`: writer под мьютексом считает байты, на 5 МБ — `.1` → `.2` (старый `.2` удаляется), открывает новый, `dup2` на fd 1 и 2. Файл и архивы `0640`, владелец root, группа — `admin`; после удачного применения конфига группа файлов меняется на `control_group` (поле уже есть, цена — один `chown`; без применённого конфига остаётся `admin`). Каталог лога не создаётся демоном (design 4.1): нет каталога — ошибка в stderr, код 1. Имена из DNS-запросов — только на debug (проверить, что так и есть). Флаг `-v` сохраняется.
12. **`wgplex check [-config dir]`** (design 13): локально, без демона и root, тот же `config.LoadDir`; вывод текстом: `config OK` либо `config error: …` по строке на ошибку, предупреждения — `warning: …` (в том числе `blockedDNSWarnings` и `checkWarnings`); коды 0 (OK, предупреждения не влияют) / 1 (ошибки) / 2 (usage). `-json`, код `3` — M3. Группа `control_group` проверяется так же, как в демоне.
13. **Флаги:** `daemon` — `-v`, `-socket`, `-config`, `-state`, `-log`; клиентские — `-socket`; `check` — `-config` (`-socket` ему не нужен: `usage`). Пути по умолчанию: `paths{Socket, ConfigDir, State, Log}` из prefix (design 3).
14. **`docs/api.md`** — не в M2 (решение пользователя: каркас делается вместе с полным контрактом в M3). `config.apply`→`config.reload` фиксируется в «Ходе работы» для сессии `wgplex-app` (CLAUDE.md: этап, меняющий API, заканчивается текстом для неё) — формулировка в конце этапа; `api_version` ещё не отдаётся.

## Не в M2

Права по методам, `control_group` как проверка членства, `mbr_check_membership`, ошибка `5`, урезание ответов, `tunnel.enable/disable`, `down -all`, пауза, снимок блокировки, `-json`, код выхода `3`, предупреждение о версиях, `docs/api.md`, точечный DNS (M4), возврат (M5), формула и каталоги (M6).

## Сигнатуры

```go
// internal/config/config.go
type Config struct {
	ControlGroup string // default "admin" (design 5, 10.1)
	// … остальное как есть
}

// internal/config/dir.go (новый)
const MaxFileSize = 1 << 20

// LoadDir reads dir (design 5, 10.2) and runs Load on the result. Every
// problem found is in the returned Errors: the directory missing, a file
// failing checkAccess, unreadable files (with a TCC hint on EPERM), Load's
// errors, an unknown control_group. A file failing checkAccess is still
// passed to Load so that its own errors are collected too.
func LoadDir(dir string) (cfg *Config, warnings []string, err error)

// fileInfo is what checkAccess needs of a file or of the directory.
type fileInfo struct {
	Name string
	Mode fs.FileMode
	UID  uint32
	Size int64
}

// checkAccess is design 5: owner root or dirUID, no group/other write bit,
// regular file (unless isDir) of at most MaxFileSize. warn: a .conf readable by
// group or others (conf reports it; the main file never does).
func checkAccess(fi fileInfo, dirUID uint32, isDir, conf bool) (warn string, err error)

// tccError wraps err of reading path with the TCC hint when it is EPERM.
func tccError(path string, err error) error

var lookupGroup = user.LookupGroup // replaced in tests

// internal/state/state.go (новый)
type State struct {
	Tunnels map[string]bool `json:"tunnels,omitempty"` // explicit toggles by tunnel name
}

// Load reads path. No file: empty State, nil error. Unreadable or broken:
// empty State and the error (the caller logs a warning, design 11).
func Load(path string) (State, error)

// Save writes s atomically: temporary file in the directory of path, 0640, rename.
func (s State) Save(path string) error

// Prune drops the toggles of tunnels not in names and reports whether it dropped any.
func (s *State) Prune(names []string) bool

// cmd/wgplex/apply.go
// switches: explicit toggles (state.json); a tunnel without an entry follows
// its autostart. Otherwise as before.
func planApply(cur, next *config.Config, switches, running map[string]bool) (nextEnabled map[string]bool, stop, start []string)

// cmd/wgplex/logfile.go (новый)
const logRotateSize = 5 << 20
type rotatingFile struct{ /* mu, path, f, size, gid */ }
func openLog(path string, gid int) (*rotatingFile, error) // appends; size from Stat
func (l *rotatingFile) Write(p []byte) (int, error)        // rotates at logRotateSize
func (l *rotatingFile) SetGroup(gid int) error             // chown file and archives
func (l *rotatingFile) Dup2Std() error                     // fd 1 and 2 → current file; repeated after rotation

// cmd/wgplex/check.go (новый)
// checkMain is "wgplex check": returns the exit code, writes to w.
func checkMain(cmd command, stdout, stderr io.Writer) int
// formatCheck renders warnings and err as the text of check and the exit code.
func formatCheck(warnings []string, err error) (out string, code int)

// cmd/wgplex/paths.go
type paths struct { Socket, ConfigDir, State, Log string }

// internal/rpc/rpc.go
// config.apply, ApplyParams — удалены; Daemon: Reload() (ApplyResult, error)
// (метод "config.reload", params нет)
```

Открытые места контракта (`test-dev` пишет по ним; неясное — в отчёт):

- `checkAccess`: владелец ни root, ни `dirUID` — ошибка; `Mode&0o022 != 0` — ошибка; `0o640` у `.conf` — warn, `0o600` — нет; для `isDir` размер и «обычный» не проверяются (нужен `IsDir`); `Size > MaxFileSize` — ошибка; не регулярный (`Mode.Type() != 0`) — ошибка. Сообщение содержит имя файла.
- `State.Load`: пустой файл — как битый; `{"tunnels":null}` и неизвестные поля — ок; `Save` не оставляет tmp-файлов при ошибке; права результата `0640`.
- `rotatingFile`: поведение ротации по design 15: `.1` → `.2`, существующий `.2` удаляется, отсутствующий `.2` — не ошибка; учёт байт при старте с непустым файлом; архивы и файл `0640`.
- `formatCheck`: `nil` ошибка → строка `config OK` и код 0; `Errors` из `n` ошибок → `n` строк `config error: …` и код 1; предупреждения — `warning: …` в обоих случаях, после ошибок.

## Файлы и зоны агентов

| Файл | Кто |
|---|---|
| `internal/config/{config,yaml,validate,dir}.go` | go-dev **A** |
| `internal/config/dir_test.go`, `controlgroup_test.go` | test-dev |
| `internal/state/state.go` | go-dev **B** |
| `internal/state/state_test.go` | test-dev |
| `cmd/wgplex/logfile.go` | go-dev **B** |
| `cmd/wgplex/logfile_test.go` | test-dev |
| `cmd/wgplex/{paths,args,apply,configdir→удалить,daemon,daemon_main,check,main}.go`, `internal/rpc/*`, `internal/router/kernel_darwin.go` (убрать `DeleteOwned`) | go-dev **C** (интеграция, после A и B) |
| `cmd/wgplex/check_test.go` | test-dev |
| существующие тесты (`apply_test.go`, `args_test.go`, `daemon_main_test.go`, `internal/rpc/*_test.go`, router) — адаптация | go-dev **C** |
| `docs/plans/m2-system-mode.md` | оркестратор |

## Шаги

1. План согласован с пользователем; коммит плана в ветку.
2. **`go-dev`, сигнатуры** (одним коммитом, `panic("not implemented")`, doc-комментарии): все новые типы и функции раздела «Сигнатуры» — `LoadDir`, `checkAccess`, `tccError`, `internal/state`, `rotatingFile`, `formatCheck`, `checkMain`, `paths`, изменение `planApply` и `rpc.Daemon.Reload` с заглушками; `make check` на сигнатурах может краснеть только в тестах, которых ещё нет.
3. Параллельно, worktree'ы, зоны не пересекаются:
   - **`go-dev` A** — `internal/config`: `LoadDir`, `checkAccess`, `tccError`, `ControlGroup` (YAML, значение по умолчанию, проверка);
   - **`go-dev` B** — `internal/state` и `cmd/wgplex/logfile.go`;
   - **`test-dev`** — тесты A, B и `formatCheck` по design и разделу «Сигнатуры», реализацию не читает.
4. Сведение A, B и тестов в ветку этапа; `make check`; расхождения тест/код — `reviewer` решает, кто неправ.
5. **`go-dev` C** — интеграция: `Reload` вместо `Apply`, чтение `LoadDir` при старте и в `Reload`, `state.json` (чтение до первого применения, запись в `setEnabled`/`disableAll`, `Prune` после применения), `planApply(…switches…)`, старт с битым конфигом + пустая синхронизация, `releaseDNS` без `captured`, удаление `DeleteOwned` и `readConfigDir`, `disableAll` без конфига — код `2`, лог (`openLog`, `Dup2Std`, `SetGroup` после применения), флаги и `paths`, `check`; адаптация существующих тестов.
6. **`reviewer`** — дифф `master...m2-system-mode`: соответствие design, плану; grep на остатки `config.apply`, `ApplyParams`, `DeleteOwned`, `readConfigDir`; ключи в логах; тесты. Исправления — `go-dev`.
7. Проверка в VM (ниже) — `general-purpose` на sonnet по шагам плана; пользователь подтверждает результат.
8. «Ход работы», текст для сессии `wgplex-app` (смена `config.apply` → `config.reload`), слияние в `master` по условиям CLAUDE.md.

## Проверка

**Unit** (дано/когда/то):

1. Каталог, где `wgplex.yaml` записываем группой → ошибка конфига; остальные ошибки тоже собраны.
2. `.conf` `0640` → предупреждение, конфиг применим; `0666` → ошибка; владелец — ни root, ни владелец каталога → ошибка.
3. Симлинк на файл с `EPERM` при чтении → текст с TCC; нет каталога → «config directory … not found»; FIFO вместо `.conf` → ошибка, демон не виснет; файл > 1 МБ → ошибка.
4. `control_group: nosuchgroup` → ошибка; `control_group` не задан → `admin`; числовой gid → без проверки.
5. `state.json` `{"tunnels":{"t1":true}}`, `t1` с `autostart: false` → `planApply` включает `t1`; запись `t1: false` при `autostart: true` → выключен; туннель без записи — по `autostart` и на `reload` (правка `autostart` действует).
6. Конфиг без `t1` → `Prune` убирает запись и сообщает, что убрал; битый `state.json` → предупреждение, всё по `autostart`.
7. Две ошибки в YAML → `formatCheck` печатает обе, код 1; хороший конфиг → `config OK`, код 0.
8. Лог 5 МБ + существующие `.1`, `.2` → `.1`→`.2`, новый файл открыт, запись продолжается; без `.2` — без ошибки.
9. `tunnel.disableAll` без конфига → код `2` (RPC-уровень).
10. Старт без конфига (битый) → синхронизация пустого состояния вызвана (проверяется на уровне чистой функции расчёта — `Table{}`; сами системные вызовы — VM).

**VM** (`general-purpose` на sonnet, `scripts/vm.sh`, клоны `wgp-check-m2-*` образа `wgp-base`, `--net-bridged`; клоны и стенд сносятся после проверки):

Стенд: вторая VM — WireGuard-сервер (`brew install wireguard-tools wireguard-go`, `wg-quick`/`wg` с интерфейсом `10.99.0.1/24`; ключи — свежие, сгенерированные в VM, в репозиторий не попадают). Клиентская VM: `make build` → `/opt/homebrew/bin/wgplex` (вне `Cellar`, prefix `/opt/homebrew`), каталоги `var/run`, `var/log/wgplex`, `var/wgplex`, `etc/wgplex` (`0700`) создаёт шаг проверки. LaunchDaemon — временный plist (`KeepAlive`, `RunAtLoad`) через `launchctl bootstrap system`.

1. **Главный критерий:** перезагрузка VM без ручного входа → демон работает (uid 0), туннель к стенду поднят, handshake есть, у сервера виден peer.
2. Старт с битым конфигом (синтаксическая ошибка YAML): демон жив, `status` — `configured: false`, `config_errors`, туннелей нет; маршруты прошлого запуска сняты, ключ DNS снят (`scutil --dns` без `127.0.0.1`). Вернуть конфиг + `reload` → туннель поднят.
3. Осиротевшее: вручную `route add … -proto2` (host-route и сетевой), остановить демон `kill -9`, запустить с конфигом без них → оба исчезли первой синхронизацией (до неё не снимались: `netstat -rn` между стартом и концом синхронизации не проверяется — достаточно итога); ключ DNS прошлой сессии при конфиге без доменов снят; при конфиге с доменами — переиздан.
4. `state.json`: `up`/`down` от root → файл `{"tunnels":…}` `0640`, `kickstart -k` → состояние восстановлено; правка `autostart` в YAML у туннеля без записи + `reload` → действует; удаление туннеля из конфига + `reload` → запись убрана.
5. Правило `fallback: block` с `via` на туннель `autostart: false` (не поднят с начала): `reject`-маршрут с флагом `2` в `netstat -rn` (не проверено на M1).
6. Лог: файл `0640` root:`admin` пишется; после `reload` с `control_group` другой существующей группой — группа файла сменилась; ротация наблюдается (заполнение до 5 МБ); паника/вывод в stderr попадает в актуальный файл; `SIGHUP`/`SIGUSR1` — демон жив; `SIGTERM` — маршруты, ключ DNS, сокет сняты, код 0.
7. CLI: `wgplex check` от `admin` (не root) — `config OK`; `chmod 0666` у `.conf` → `config error`, код 1; `check -socket …`/`reload -config …` → usage, код 2; `control_group: nosuchgroup` → ошибка.

Не проверяется: живой TCC (`~/Documents`) — только unit; реальный занятый порт DNS — M4.

## Факты spike

Из чтения кода (2026-11-03):

- `Sync` снимает наши host-route'ы вне таблицы; `d.hosts` после рестарта пуст → осиротевшие host-route'ы уходят первой синхронизацией (решение 8, 10 это гарантируют).
- `Apply` вызывает `syncNow` только в составе применения; `shutdown` выполняет `syncTable(endpointRoutes(d.table), …)` только при `d.synced`.
- `releaseDNS` в `Apply` зависит от `d.captured` — после рестарта чужой ключ не снимается (решение 10 исправляет).
- Запись состояния переключателей `setEnabled` — в M1 есть, но только в памяти.

Проверить в ходе работы (результат записать сюда):

- [ ] `os/user.LookupGroup("admin")` под cgo в LaunchDaemon (root) и из Terminal — находит; `nosuchgroup` даёт `user.UnknownGroupError`.
- [ ] `dup2` на fd 1 и 2 в Go: паника после ротации идёт в новый файл (`syscall.Dup2` на arm64 отсутствует — использовать `unix.Dup2`/`Dup3`).
- [ ] `wgp-base`: автологин и FileVault — «без ручного входа» подтверждено на M1; «без сессии loginwindow» не подтверждалось.
- [ ] Стенд: WireGuard-сервер на macOS-VM (userspace `wireguard-go`) принимает peer из соседней VM в bridged-сети.

## Риски

- **Интеграция C — самая тяжёлая задача** (`daemon.go` ~1000 строк, три смысловых изменения в `Apply`/старте); поэтому она одна и идёт после A/B.
- **Изменение семантики `reload`:** туннели без записи после `reload` снова следуют `autostart` (раньше держали текущее состояние). Это design 10.2, но видимое поведение меняется — отражается в «Ходе работы».
- **Битый конфиг при старте до M3 не блокирует `fallback: block`** (нет снимка) — ограничение этапа, design 4.1 полностью — с M3.
- **`dup2` и ротация** — тонкое место; unit-тест на ротацию и проверка паники в VM.
- **Стенд — новая инфраструктура:** время на отладку WireGuard-сервера не в коде; при затруднении — только пользователь решает, упрощать ли проверку.
- **Несовпадение прав `check` и демона:** `check` от обычного пользователя читает файлы с его правами (TCC Terminal), демон — нет (design 18); сам `check` этого не ловит.

## Вопросы пользователю

1. `control_group` на M2: существование через `os/user.LookupGroup` вместо Directory Services (решение 4) — ок?
2. Группа файлов лога меняется на `control_group` после применения конфига уже в M2 (решение 11), а не в M3 — ок? Альтернатива: везде `admin` до M3.
3. Каталоги `var/wgplex` и `var/log/wgplex` демоном не создаются (формулы ещё нет, VM-шаг создаёт их) — читаю design 4.1 так: «недостающее внутри» = файлы; верно?
4. `docs/api.md` в M2 не трогаем (весь контракт — M3); текст для `wgplex-app` про `config.reload` отдаём в конце этапа. Ок?
5. Тесты `test-dev` пишет по design до реализации (шаги 2–3), а не только ревью — как в CLAUDE.md; согласны с зонами файлов в таблице?

## Ход работы

- [ ] План согласован
