# M1 — перенос

Статус: план утверждён 2026-10-20, в работе. Ветка `m1-port`.

**Цель:** код Wirefork работает как wgplex — один бинарник, свои имена, пути и метки, без приложения, pkg и пользователя за консолью. Поведение ядра (туннели, маршруты, DNS, здоровье) не меняется. Текст разделов Wirefork, на которые ссылается `design.md`, переносится в него с заменами 4.4.

Правила — design 3, 4.1, 4.4, 13, 16.2, 21.1 (M1); CLAUDE.md.

**Источник:** `wirefork` `master` на `c86f993` (merge M11, v1.2.0) — зависимость 21.3 выполнена.

## Факты (до работы)

1. Wirefork: `cmd/wireforkd` (демон, ~2,5 тыс. строк без тестов), `cmd/wf` (CLI), `internal/{config,router,dns,tunnel,health,netwatch,rpc}`; Go 1.27.1, зависимости — echo v5, miekg/dns, jrpc/v2, yaml v3, x/net, x/sys, wireguard. cgo нет.
2. Специфика Wirefork в коде: `RTF_PROTO1` (`router/sync_darwin.go`, `router/kernel_darwin.go`), UUID захвата и `:53` (`dns`, `cmd/wireforkd/daemon.go`), `SocketPath` (`rpc/rpc.go`), `wirefork.yaml` (`config/config.go`), console user (`netwatch.Console`, `ReadConsole`, `rpc.ConsoleUID`, `events.go`: `initConsole`, `checkConsole`, `resetUser`), переключатели по uid (`toggles.go`, `/Library/Application Support/wirefork/toggles.json`), лог через `-log`, pid-файл и SIGUSR1 (`logfile.go`), путь конфига `~/Library/Application Support/wirefork` (`cmd/wf/args.go`).
3. RPC Wirefork: `config.apply` (файлы от клиента), `tunnel.setEnabled`, `tunnel.disableAll`, `status.get`, `diag.explain`, `diag.routes`. Доступ — root и владелец `/dev/console` (HTTP 403 остальным).

## Решения

1. **Один пакет `cmd/wgplex`**, демон — подкоманда `daemon`. Файлы `cmd/wireforkd/*` и `cmd/wf/*` сливаются в один `package main`; конфликты имён — переименованием (`run` демона → `runDaemon`, `usage` и т.п.). Отдельного `internal/daemon` нет (KISS, структура CLAUDE.md).
2. **Prefix при запуске (design 3)** — чистая функция `brewPrefix(exe, goarch string) string` (exe — уже без симлинков) и тонкий `defaultPrefix()` поверх `os.Executable` + `filepath.EvalSymlinks` + `runtime.GOARCH`. Пути — `paths{Socket, ConfigDir string}` из prefix; на M1 только эти два.
3. **Переключатели — только в памяти** до M2 (design 21.1: «удалены переключатели на пользователя», файл — `state.json` в M2). `toggles.go` и файл удаляются; первое применение после старта — по `autostart`, повторное сохраняет переключатели, как в Wirefork. `planApply` теряет параметр `saved`.
4. **RPC — только root** до M3: `allow` = `uid == 0`. HTTP 403 остальным остаётся до M3 (там — права по методам и ошибка `5`). CLI на 403: `permission denied: run as root`.
5. **Конфиг — `config.apply` Wirefork до M2:** `wgplex reload [-config dir]` читает каталог (по умолчанию `<prefix>/etc/wgplex`) и отправляет файлы; главный файл — `wgplex.yaml`.
6. **DNS — как в Wirefork до M4:** резолвер `127.0.0.1:53`, захват `SupplementalMatchDomains = [""]` через `scutil`, снятие ключа при старте; меняется только UUID сервиса на собственный (новый, постоянный, константа в коде). Снятие при выходе пользователя уходит вместе с console user.
7. **Уборка при старте — как в Wirefork до M2** (`router.DeleteOwned`, `releaseDNS`): «без предварительного снятия» — задача M2.
8. **Логи — только stderr до M2:** `-log`, pid-файл и переоткрытие по SIGUSR1 удаляются; SIGUSR1 и SIGHUP — `signal.Ignore` (design 4.1). Файл лога с ротацией — M2.
9. **Не от root** — ошибка в stderr и выход с кодом `0` (design 4.1; в Wirefork — `1`).
10. **Каталоги не создаются:** нет `<prefix>/var/run` — ошибка захвата сокета в stderr (design 4.1). Формулы ещё нет: в VM каталог создаётся шагом проверки.
11. **Флаги:** клиентские команды — `-socket` и `-config` (только `reload`); `daemon` — `-v`, `-socket`. `-config`, `-state`, `-log` у `daemon` — M2. RPC-методы и их имена — как в Wirefork до M3 (`tunnel.setEnabled`, без `daemon.pause`); `down -all`, `pause`, `resume`, `check`, `-json` — не в M1.
12. **`wgplex version`** — `wgplex <версия>` (только CLI; версия демона в `status.get` — M3). Версия — файл `VERSION` (`0.1.0-dev` до релиза M6), `-ldflags -X main.version=…`; без ldflags (`go run`, тесты) — `dev`.
13. **`Makefile`:** `check` (`gofmt -l`, `go vet`, `go test`), `build` (design 16.2: `CGO_ENABLED=1`, срез `amd64` — `CC="clang -arch x86_64"`, `lipo`, `codesign --sign -`, ldflags), `clean`. `release` — M6. Приложения, pkg, `lint-packaging`, `app-test` нет.
14. **Тесты Wirefork переносятся все**, кроме относящихся к удалённому (console user, файл переключателей, `logfile`); тесты `planApply` с `saved` — адаптируются (без сохранённых переключателей). Ожидания с `RTF_PROTO1`, UUID, путями — на новые значения.
15. **Тексты** демона и CLI: `wireforkd`/`wf` → `wgplex`, `Wirefork` → `wgplex`. JSON-поля API не меняются (api.md — M3).
16. **Перенос текста дизайна** (отдельная задача Д): разделы `design.md` с «как в Wirefork» (6, 7, 8, 9, 10.1, 10.2, 13 — колонка `CHECK`, 14 — поля `status.get`, ошибки, 18 — ограничения маршрутизации и DNS) получают полный текст из `wirefork/docs/design.md` с заменами из 4.4 и именами wgplex. Ссылки «Wirefork N» на перенесённое заменяются на свои разделы; ссылки на Wirefork остаются только как история («в Wirefork было так»). 4.4 остаётся (что заменено и почему). Смысл не меняется; всё, что не ложится однозначно в 4.4, — вопрос в отчёте, а не решение. Временные оговорки M1 (решения 3–8) в `design.md` не пишутся — они в этом плане.
17. `.gitignore`: `build/`.

## Сигнатуры (новое, остальное — перенос)

```go
// cmd/wgplex/paths.go
type paths struct {
	Socket    string // <prefix>/var/run/wgplex.sock
	ConfigDir string // <prefix>/etc/wgplex
}

// brewPrefix returns HOMEBREW_PREFIX for the executable at exe (symlinks
// already resolved) built for goarch (design 3): everything before
// "/Cellar/" when exe contains it, otherwise /opt/homebrew on arm64 and
// /usr/local on amd64.
func brewPrefix(exe, goarch string) string

// pathsFor derives the default paths from prefix (design 3).
func pathsFor(prefix string) paths

// defaultPrefix is brewPrefix of os.Executable after EvalSymlinks and
// runtime.GOARCH; on an error of either — the goarch default.
func defaultPrefix() string
```

`parseArgs` (из `cmd/wf/args.go`) — тот же вид, команды `status explain routes up down reload daemon version`, флаги по решению 11; `command` получает поля `Socket` и `Verbose`.

Открытые места контракта (`test-dev` пишет тесты по ним; неясность — в отчёт):

- `brewPrefix`: `/Cellar/` ищется первое вхождение; prefix без завершающего `/`; `/opt/homebrew/Cellar/wgplex/0.1.0/bin/wgplex` → `/opt/homebrew`; `/Users/u/brew/Cellar/wgplex/0.1.0/bin/wgplex` → `/Users/u/brew`; `/Users/u/src/wgplex/build/wgplex` + `arm64` → `/opt/homebrew`, + `amd64` → `/usr/local`; неизвестная архитектура — `/opt/homebrew`.
- `parseArgs(args []string, def paths)`: флаги — до или после команды и её аргумента; `-socket` — у всех команд; неизвестная команда, лишний или пустой аргумент — `errUsage` (код 2); `-config` при командах кроме `reload` — `errUsage`; `daemon` и `version` без аргументов.

## Файлы

| Файл | Что |
|---|---|
| `go.mod`, `go.sum` | модуль `github.com/mrFokin/wgplex`, зависимости Wirefork |
| `internal/*` | копия Wirefork; импорт-пути; `RTF_PROTO2`; UUID; `wgplex.yaml`; без `netwatch.Console`, `ReadConsole`, `rpc.ConsoleUID`, `SocketPath` |
| `cmd/wgplex/*` | слияние `cmd/wireforkd` и `cmd/wf`; `paths.go`, `version`; без `toggles.go`, `logfile.go`, console user |
| `cmd/wgplex/paths_test.go`, `cmd/wgplex/args_test.go` | `test-dev` |
| `Makefile`, `VERSION`, `.gitignore` | решения 12, 13, 17 |
| `docs/design.md` | задача Д (решение 16), шапка статуса |

## Шаги

1. План утверждён пользователем.
2. **`go-dev`, задача А** (worktree, ветка `m1-port`): копия кода, переименования (модуль, `RTF_PROTO2`, UUID, имена файлов и текстов), удаление console user, переключателей по uid, лога через `-log`, сокета-константы; `Makefile`, `VERSION`; сигнатуры `paths.go` (`panic`), `parseArgs` с новыми командами. Перенесённые тесты зелёные (кроме тестов новых функций — их ещё нет). Коммит.
3. Параллельно:
   - **`go-dev`, задача Б**: реализация `paths.go`, `daemon`/`version` в `main`, решения 4, 8, 9, 11, 12; свои тесты — не в `paths_test.go` и `args_test.go`;
   - **`test-dev`**: `cmd/wgplex/paths_test.go`, `cmd/wgplex/args_test.go` по design 3, 13 и разделу «Сигнатуры»;
   - **агент `general-purpose`, задача Д**: перенос текста дизайна (решение 16), отчёт с вопросами.
4. Сведение: `make check`, расхождения тест/код — `reviewer` решает, кто неправ.
5. **`reviewer`** — дифф ветки: соответствие дизайну и плану, остатки Wirefork (`grep` по `wirefork`, `wireforkd`, `RTF_PROTO1`, старому UUID, `/var/run/wirefork`, `Application Support`), перенос текста дизайна против исходника. Исправления.
6. **Проверка в VM** (оркестратор, `scripts/vm.sh`, мост) — раздел ниже.
7. «Ход работы», статус плана, слияние по условиям CLAUDE.md.

## Проверка в VM

VM `wgp-check-m1`, бинарник `make build` копируется в `~/wgplex/build/wgplex` (вне `Cellar`: prefix `/opt/homebrew`).

1. `mkdir -p /opt/homebrew/var/run /opt/homebrew/etc/wgplex` от `admin`; `chmod 0700` каталога конфига.
2. Конфиг: туннель `t1` (`routes: rules`, `autostart: true`, endpoint — адрес в сети VM, на котором никто не слушает; ключи — `head -c32 /dev/urandom | base64`), сервис с CIDR `203.0.113.0/24` и сервис с доменом `example.net`, правило `via: [t1]`, второе правило `fallback: block` с CIDR `198.51.100.0/24`.
3. `wgplex daemon` от `admin` — сообщение в stderr, код `0`.
4. `sudo ./build/wgplex daemon -v &` — слушает `/opt/homebrew/var/run/wgplex.sock`; второй экземпляр — ошибка на сокете.
5. `wgplex status` от `admin` — `permission denied`; `sudo wgplex reload` — применён; `sudo wgplex status` — `t1` поднят (handshake нет, это нормально без стенда).
6. `netstat -rn` — маршруты `203.0.113.0/24` на utun и `198.51.100.0/24` reject с флагом `2` (`RTF_PROTO2`, в выводе `netstat` — `2`), без флага `1`; `scutil --dns` — резолвер `127.0.0.1` с нашим UUID; `dscacheutil -q host -a name example.net` — запрос виден в логе `-v`.
7. `sudo wgplex down t1`, `up t1` — маршруты уходят и возвращаются.
8. `SIGHUP`, `SIGUSR1` — демон жив; `SIGTERM` — маршруты с флагом `2`, ключ DNS и сокет сняты, код `0`.
9. `version` — `wgplex 0.1.0-dev`.

## Ручные шаги (пользователь)

Нет: проверка без GUI, выполняется в VM агентом. Пользователь подтверждает результат перед слиянием.

## Готово, когда

- `make check` зелёный, `make build` даёт universal `build/wgplex` (`lipo -archs` — `x86_64 arm64`, `codesign -v` проходит).
- В коде и текстах нет остатков Wirefork (шаг 5).
- Проверка в VM пройдена, результат — в «Ход работы».
- `design.md` без «как в Wirefork»: перенесённые разделы полные, 4.4 применена.

## Вопросы пользователю

1. Переключатели на M1 — только в памяти: да (пользователь, 2026-10-20).
2. `VERSION` — `0.1.0-dev` до релиза M6 (пользователь, 2026-10-20).

## Ход работы

- [x] План утверждён (2026-10-20): переключатели в памяти, `VERSION` = `0.1.0-dev`
- [x] Шаг 2 — задача А (`go-dev`): 768c475, слита (03340dc), `make check` зелёный. Сверх плана: удалён `dns.Server.Reset` (не вызывался без сброса пользователя); `parseArgs(args, def paths)`; флаги и до, и после команды (design 13 пишет `wgplex daemon -v`, `reload -config`); `-socket` принимается всеми командами. Комментарии кода ссылаются на нумерацию разделов Wirefork — перенумерация в задаче Б. Worktree агентов создаются от `master`, не от ветки этапа — агенты переставляют ветку на `m1-port` сами
- [x] Шаг 3 — задача Б (`go-dev`) и тесты (`test-dev`): запущены. Оба куска выполнены, но не сведены: `b809e1e` (`feat(cmd)` — реализация `paths.go`, демон не от root, отсутствие каталога сокета; ветка `worktree-agent-a57514ad30f219e84`), `f059d1d` (`test(cli)` — `args_test.go`, `paths_test.go`; ветка `worktree-agent-a332a2805b5a1fdce`). Композиционная проверка (2026-10-21, одноразовый worktree, без коммитов): одно расхождение — `TestParseArgsUsage/down_all_not_in_M1`: `parseArgs` задачи А пускает `down` с аргументом, тест test-dev требует `errUsage` (решение 11). На решение `reviewer` (шаг 4)
- [x] Задача Д (перенос текста дизайна): запущена раньше шага 3 — от кода не зависит, файлы не пересекаются; e7f737d, слита в `m1-port` (fast-forward). 7 вопросов пользователю решены (2026-10-21): 1 — в (host-route'ы до endpoint'ов несуществующих туннелей — ограничение в 18), 2 — а (как перенесено), 3 — а (сброс кэша mDNSResponder при каждой записи ключа), 4 — да (перезапуск configd остаётся в 18), 5 — а (формулировка про PTR принята), 6 — а (пауза выше ошибки конфига в приоритете `icon`), 7 — б (уточнено «чтение событий — без cgo» в 6). Правки — разделы 6 и 18 `design.md`. Текст вопросов восстановлен из транскрипта сессии Claude Code от 2026-10-20 (отчёт агентом `abf13145d592dd983` не был записан в git)
