# M6 — поставка

Статус: план на согласовании. Ветка `m6-delivery` от `master` (529804b).

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

- [ ] План согласован
