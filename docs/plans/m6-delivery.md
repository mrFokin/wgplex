# M6 — поставка

Статус: слит в `master`. Ветка `m6-delivery` от `master` (529804b).

**Цель:** движок ставится одной командой `brew install mrfokin/tap/wgplex` из готового universal-архива; формула создаёт каталоги и шаблон конфига, запускает демон как службу root, корректно обновляется и удаляется. Правила — design 3, 4.1, 10.3, 16, 21.1 (M6); CLAUDE.md; факты H1–H18 из `m0-spike.md`.

## Контекст

- Есть: `make build` (universal, ad-hoc подпись), `VERSION` = `0.1.0-dev`, `wgplex check -config`, выход демона не от root с кодом 0 (`daemon_main.go`).
- Нет: `make release`, шаблона `share/wgplex/wgplex.yaml`, `LICENSE`, `README`, формулы, репозитория `mrFokin/homebrew-tap` (проверено `gh`).
- `api.md` не меняется, `api_version` тот же.

## Решения

1. **Архив** `wgplex-X.Y.Z-darwin-universal.tar.gz`, без общего верхнего каталога: `bin/wgplex`, `share/wgplex/wgplex.yaml`, `LICENSE`. Рядом `….tar.gz.sha256`. Формула: `bin.install "bin/wgplex"`, `pkgshare.install "share/wgplex/wgplex.yaml"`.
2. **`make release`**: `check` → `build` → архив в `build/` + sha256. Версия — из `VERSION`; перед релизом `0.1.0-dev` → `0.1.0` отдельным коммитом (после согласования). Тег и `gh release` — не делает (design 16.3, вручную после одобрения).
3. **Шаблон** `share/wgplex/wgplex.yaml` — целиком закомментирован: что положить в каталог, пример design 10.1. Тест: шаблон в каталоге `0700`/файл `0600` проходит `wgplex check -config` с нулём туннелей.
4. **Формула** живёт в репозитории tap (`Formula/wgplex.rb`), в этом репозитории её нет. Состав — design 16.4: `url`/`sha256`/`version`, `depends_on :macos`, `post_install_steps` (`etc/wgplex` `0700` + `wgplex.yaml` `0600` через `unless_path_exists`; `mkdir_p` для `var/wgplex`, `var/log/wgplex`, `var/run`), `service do` (`require_root true`, `keep_alive successful_exit: false`, `log_path`/`error_log_path`), `caveats`, `test do`.
5. **Локально до публикации:** tap — каталог рядом с репозиторием (`git init`, без push); в VM формула берёт архив по `file://` (копируется через `vm.sh cp`). Публикация (репозиторий tap, тег, релиз, push) — только после вашего одобрения.
6. **Не в M6:** приложение и cask (A5); CI; релиз приложения.

## Задачи и порядок

1. **`go-dev`** (worktree): `Makefile` (`release`), `share/wgplex/wgplex.yaml`, `LICENSE` (MIT), короткий `README.md` (EN: установка, запуск, удаление).
2. **Параллельно** (файлы не пересекаются):
   - `test-dev`: тест шаблона (решение 3) по design 10.3, не глядя в реализацию.
   - `go-dev` (opus): формула в локальном tap по design 16.4 и фактам M0 (H1–H18).
3. **Ревью** (`reviewer`): дифф репозитория и формула.
4. **Проверка в VM** (`general-purpose`, sonnet; клоны `wgp-check-m6-*`, bridged; сносятся):
   1. чистый prefix: `brew install` из локального tap → `bin/wgplex`, шаблон в `etc/wgplex` (`0700`/`0600`), `var/wgplex`, `var/log/wgplex`, `var/run` — владелец `admin`; `brew doctor` без «not writable»;
   2. `brew test wgplex`; `wgplex version`; `wgplex check` на шаблоне;
   3. `sudo brew services start --sudo-service-user=root wgplex` → демон жив, сокет есть, `status` отвечает; лог в `var/log/wgplex`;
   4. `brew services restart` без `sudo` → копия пользователя выходит с кодом 0, не перезапускается, в stderr — сообщение;
   5. `upgrade` (вторая сборка `0.1.1-test`): одна версия в `brew list --versions`, конфиг цел, шаблон не перезаписан, после `sudo … restart` версии CLI и демона совпадают;
   6. `sudo brew services stop` → `brew uninstall`: plist удалён, остатки только `etc`, `var/wgplex`, `var/log/wgplex`;
   7. повторная установка поверх остатков не затирает конфиг.
5. **Документы:** «Ход работы», правки design 16 по фактам.
6. **Слияние** по CLAUDE.md после подтверждения вами. Публикация (tap, тег `v0.1.0`, `gh release`, формула) и финальная проверка на хосте — после одобрения; шаги хоста: остановить Wirefork, перенести конфиг, проверить, вернуть Wirefork.

## Вопросы к пользователю

1. **Публикация `0.1.0`:** design 21.3 — первый релиз обоих репозиториев после M6 и A5, промежуточных нет, а строка M6 говорит «релиз `0.1.0`». Предлагаю: M6 заканчивается готовой формулой и проверкой в VM по локальному архиву; репозиторий tap, тег и `gh release` — отдельным шагом после A5 (или сразу, если хотите раньше). Так?
2. **`LICENSE` и `README`** (в репозитории их нет, design 16.1 требует MIT): добавить в M6? Копирайт — «Denis Fokin»?
3. **Прогон VM:** те же ограничения, что в M4/M5 (bridged, клоны `wgp-check-m6-*`)? Homebrew ставится в клон из интернета (в `wgp-base` он уже есть).

## Ход работы

- [x] План согласован (2026-11-05): «да» на все три рекомендации (публикация 0.1.0 — после A5; LICENSE MIT «Denis Fokin» и README — в M6; VM bridged)
- [x] Сведено в `m6-delivery`: репо-файлы (6f866c5), тест шаблона (cherry-pick c745836: worktree test-dev стоял на старом коммите), формула — локальный tap `~/Projects/claude/homebrew-tap` (ebbc7f9, не публиковалась). `make check` зелёный.
- [x] Ревью (reviewer, opus): блокеров нет. Исправлено: `make release` требует `VERSION` вида `X.Y.Z` (для VM-сборок — `make release VERSION=0.1.1`); архив без xattr и данных машины сборки (root:wheel); формула — строгая проверка версии в `test do` и в caveats «игнорировать строку brew без опции». Принято: тест шаблона не проверяет раскомментированный пример (пример проверен вручную, совпадает с design 10.1).
- Открыто: в формуле нет явного `version` (Homebrew берёт из `url`) — формулировку design 16.3 п.2 поправить после согласования.
- [x] Проверка в VM (2026-11-05, `general-purpose` на sonnet, клон `wgp-check-m6-a`, bridged, снесён; архивы 0.1.0/0.1.1 по `file://`, HEAD m6-delivery после ревью): сценарии 1, 2, 3, 5, 6, 7 и `brew audit --strict` — PASS.
  - Установка: `post_install_steps` срабатывает сам при `install`; `etc/wgplex` 0700, `wgplex.yaml` 0600, `var/wgplex`, `var/log/wgplex`, `var/run` — admin; `brew doctor` чист; LICENSE в keg; `brew test` проходит; `brew trust` не понадобился.
  - Служба root: plist `UserName=root`, `KeepAlive/SuccessfulExit=false`; владельцы keg/симлинков остались admin, root владеет только `wgplex.log` (root:admin 0640).
  - `upgrade`: одна версия, конфиг цел; до restart `wgplex version` предупреждает о старом демоне, после `sudo … restart` версии совпадают.
  - Удаление: `stop` → plist и демон сняты, сокет удалён, маршрутов/DNS не осталось (проверен пустой конфиг); остатки — `etc/wgplex`, `var/wgplex`, `var/run`, лог.
  - **Сценарий 4 — FAIL:** `brew services restart` без `sudo` создаёт LaunchAgent пользователя; launchd не может открыть `StandardOutPath` (`wgplex.log` — root:admin 0640), `posix_spawn … Permission denied`, `EX_CONFIG` (78), перезапуск каждые 10 с, до кода демона дело не доходит. После `chmod 664` лога агент пишет ошибку про root, выходит с 0 и не перезапускается. Вред — только шум (root-служба не пострадала). `brew services stop` без `sudo` снимает агента, root-plist остаётся.
  - Не проверено: туннели/маршруты/DNS под root из brew-установки, перезагрузка VM, `start` без `--sudo-service-user`, реальный релиз на GitHub.
- [x] Решение пользователя по сценарию 4 (2026-11-05): лог для launchd доступен пользователю. Реализация отличается от буквального «`wgplex.log` 0664»: демон при каждом открытии ставит `wgplex.log` 0640 root (`logfile.go`), поэтому формула создаёт отдельный `var/log/wgplex/launchd.log` (0664, владелец пользователь) и направляет в него `log_path`/`error_log_path`; `wgplex.log` остаётся 0640, код демона не менялся. Правки design 4.1, 10.3, 15, 16.3 (версия — из `url`), 16.4.
- [x] Повторная проверка в VM (`wgp-check-m6-b`, снесён): A–D PASS. Копия без `sudo` выходит с кодом 0, `runs` не растёт, в `launchd.log` — «must run as root»; root-служба цела; `launchd.log` 0664 admin после install/reinstall (права ставятся при каждом `post_install`); root владеет только `wgplex.log` и сокетом. Замечание: `brew doctor` в этом прогоне дал предупреждения про tap (`homebrew-core`, ветки tap) — артефакт окружения проверки (переменные `HOMEBREW_NO_*`, tap без origin), в первом прогоне был чист; про wgplex замечаний нет.
- [x] Слияние в `master` (2026-11-05): `make check` зелёный на результате, пользователь подтвердил проверку VM. Публикация (tap, тег v0.1.0, gh release) — после A5; шаги хоста — за пользователем.
- [x] Релиз `0.1.0` (2026-11-05, одобрено пользователем): `VERSION` → `0.1.0`, `master` отправлен в `mrFokin/wgplex` (fast-forward bab7b20 → e688379), тег `v0.1.0`, релиз с архивом и sha256 (`8f563a36…`); репозиторий `mrFokin/homebrew-tap` (ветка `main`) с формулой, sha256 сверен с архивом на GitHub.
- [x] Проверка релиза в VM (`wgp-check-m6-c`, снесён): `brew install mrfokin/tap/wgplex` из удалённого tap без подмен, `brew test`, `brew audit --strict`, служба root, версии CLI и демона `0.1.0`, `stop` → `uninstall` → `untap` — PASS. Tap доверен автоматически (`brew trust` не нужен). Бинарник ad-hoc, карантина нет. `brew doctor` — только предупреждение про сертификаты `/etc/ssl/cert.pem` образа, к wgplex не относится.
- Осталось за пользователем: финальная проверка на хосте (остановить Wirefork, перенести конфиг, проверить, вернуть Wirefork).

### Текст для сессии `wgplex-app`

Движок `0.1.0` опубликован: `brew install mrfokin/tap/wgplex`, запуск `sudo brew services start --sudo-service-user=root wgplex`. `api_version` = 1, `api.md` не менялся с M3. Релиз: https://github.com/mrFokin/wgplex/releases/tag/v0.1.0. A5 разблокирован.
