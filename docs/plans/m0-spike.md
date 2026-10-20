# M0 — spike

Статус: план утверждён 2026-10-20, идёт реализация. Ветка `m0-spike`.

**Цель:** проверить в VM то, на чём держатся решения дизайна, до переноса кода: точечный захват DNS (design 8), проверку членства через `dsmemberutil` (5), `SMAppService.mainApp` с ad-hoc подписью (17.5), неподписанный cask из стороннего tap (17.1). Попутно — инструмент VM для всех следующих этапов: образ `wgp-base` и `scripts/vm.sh`.

Результат этапа — `scripts/vm.sh`, раздел «Факты spike» этого плана и правки `design.md` по фактам (после согласования). Кода движка нет; `Makefile` появляется в M1.

Правила — design 5, 8, 17.1, 17.5, 20, 21; CLAUDE.md, «Root и система».

## Факты (до spike)

«изв.» — известное поведение, spike подтвердит; «WF» — факты Wirefork (`wirefork/docs/plans/m10-distribution.md`).

1. **Хост:** Apple M5, macOS 26.6.2, Homebrew 7.0.10, Xcode (Swift 6.4), Go 1.27.1, tart 2.41.1 (`~/bin/tart`, из релиза GitHub: формула tap `cirruslabs/cli` на Homebrew 7 не ставится — WF 10). Wi‑Fi хоста — `en0`. На хосте постоянно работают Wirefork и сторонний VPN (`utun8`).
2. **Образы в `~/.tart`:** `ghcr.io/cirruslabs/macos-tahoe-vanilla:latest` (macOS 26, без Xcode и brew, `admin/admin`, SSH по паролю) и `wf-base` (клон Wirefork, его не трогаем).
3. **Не больше двух macOS-гостей одновременно** — ограничение Virtualization.framework (изв.).
4. **Bridged:** `tart run --net-bridged=en0`; адрес VM — `tart ip --resolver=arp` (DHCP-сервер не tart, изв.). Wi‑Fi‑точки иногда не пропускают чужие MAC через клиента — тогда NAT (design 20).
5. **`tart exec`** работает только с гостевым агентом в VM (изв.); есть ли агент в vanilla-образе — проверит spike.
6. **Gatekeeper в образе выключен** (`spctl --status` → `assessments disabled`, WF S2); для проверки 4 включается в клоне.
7. **DNS-ключи** `State:/Network/Service/<UUID>/DNS` пишет root через `scutil` (`d.init`, `d.add`, `set`) — Go в VM не нужен (изв.). `dig` идёт мимо mDNSResponder; через системный резолвер — `dscacheutil -q host -a name …` и `dns-sd -G v4 …` (изв.).
8. **`sshpass` на хосте нет.** Первый вход по паролю — через `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force` (OpenSSH ≥ 8.4, изв.).

## Решения

1. **`wgp-base` — из `macos-tahoe-vanilla`, не из `wf-base`:** у `wf-base` своя история. Проверки только на macOS 26 (принято пользователем 2026-10-20). Поведение 13–15 может отличаться (Gatekeeper изменился в 15, `SMAppService` и mDNSResponder — от версии к версии), Homebrew официально поддерживает не все версии от 13; проблемы на старых версиях решаются по мере появления, design 2 не меняется.
2. **Отдельный ключ для VM** — `~/.ssh/wgplex-vm` (ed25519, без пароля), `vm.sh` создаёт его, если нет. Основной ключ хоста с сертификатом в VM не попадает.
3. **`vm.sh` меняет только `wgp-check-*`.** `wgp-base` собирается так: клон vanilla → `wgp-check-base` → настройка → `tart clone wgp-check-base wgp-base` → `wgp-check-base` удаляется. Сам `wgp-base` только клонируется; пересборка — `vm.sh base --force` (удаляет `wgp-base`, кроме этого `vm.sh` его не трогает).
4. **Помощники spike** (тестовый DNS-сервер, тестовое приложение, `.dmg`, tap) — в scratchpad сессии `m0-spike/`, в репозиторий не идут. Факты и команды воспроизведения — в «Факты spike». Код DNS из M4 будет настоящим, а не из spike.
5. **Агенты spike — `general-purpose`, не `Explore`/`Plan`:** им нужно собирать бинарники и писать скрипты, а `Explore`/`Plan` без записи файлов. Это отступ от формулировки CLAUDE.md — подтвердите или поправлю CLAUDE.md.
6. **Две VM параллельно** (факт 3): `wgp-check-dns` — проверки 1–2 (без GUI), `wgp-check-gui` — проверки 3–4 (окно VM, шаги пользователя).

## `scripts/vm.sh`

bash, без зависимостей кроме `tart`, `ssh`, `scp`. Имя VM в командах — суффикс: `vm.sh up dns` → `wgp-check-dns`.

```
vm.sh base [--force]        собрать wgp-base (решение 3)
vm.sh up <name> [--gui] [--nat] [--dir <path>]
                            клон wgp-base → wgp-check-<name>, запуск в фоне, ждёт SSH, печатает IP
vm.sh ssh <name> [cmd...]   ssh admin@<ip> ключом wgplex-vm (без known_hosts)
vm.sh cp <name> <src>... <dst>   scp на VM (dst — путь в VM)
vm.sh get <name> <src> <dst>     scp с VM
vm.sh ip <name>
vm.sh down <name>           остановить и удалить
vm.sh list                  только wgp-check-* и wgp-base
```

- По умолчанию — `--net-bridged=en0` (интерфейс — `WGP_VM_IF`), IP — `tart ip --resolver=arp`. `--nat` — сеть tart по умолчанию и `networksetup -setdnsservers` на `1.1.1.1 9.9.9.9` в VM.
- `--gui` — с окном (для шагов пользователя), иначе `--no-graphics`. `--dir` — общая папка `--dir=spike:<path>:ro`.
- `tart run` — в фоне, лог — `~/.tart/vms/wgp-check-<name>/run.log`; `down` — `tart stop`, затем `tart delete`.
- Защита: любое действие, кроме `clone` из `wgp-base`, — только над именем `wgp-check-*`; иначе выход с ошибкой.
- `base` настраивает `wgp-check-base` по SSH (сначала паролем через `SSH_ASKPASS`, факт 8):
  - ключ `wgplex-vm.pub` в `~admin/.ssh/authorized_keys`;
  - `/etc/sudoers.d/admin`: `admin ALL=(ALL) NOPASSWD: ALL`;
  - sshd: `PasswordAuthentication no`, `KbdInteractiveAuthentication no` (drop-in в `/etc/ssh/sshd_config.d/`), проверка: вход паролем отклоняется;
  - Homebrew — официальный `install.sh` с `NONINTERACTIVE=1`, `brew` в `PATH` (`~/.zprofile`);
  - гостевой агент tart: если нет — ставится (способ — по факту spike: формула `cirruslabs/cli/tart-guest-agent` или пакет из релиза GitHub), запуск через launchd; проверка — `tart exec wgp-check-base true`;
  - выключение, `tart clone`, удаление `wgp-check-base`.
- Проверка без VM: `bash -n scripts/vm.sh` (`shellcheck` на хосте нет, не ставим).

## Проверки spike

### 1. Точечный захват DNS (`wgp-check-dns`, агент)

Помощник: `dnsspike` — Go, `GOOS=darwin GOARCH=arm64`, без зависимостей (разбор вопроса и ответ A вручную или `golang.org/x/net/dns/dnsmessage`): слушает UDP+TCP `127.0.0.1:<port>`, на любой A отвечает заданным адресом, пишет в stdout каждое имя.

Сценарий (root в VM, `scutil`):

1. `dnsspike -addr 127.0.0.1:5354 -answer 10.0.0.1` («wgplex»), `dnsspike -addr 127.0.0.1:53 -answer 10.0.0.2` («чужой VPN»).
2. Сервис W (свой UUID): `ServerAddresses = [127.0.0.1]`, `ServerPort = 5354`, `SupplementalMatchDomains = [500 зон: z0001.spike.test … ; example.com]`.
3. Сервис V (другой UUID): `ServerAddresses = [127.0.0.1]` (порт 53), `SupplementalMatchDomains = [""]`; варианты — V до W и после W, с `SupplementalMatchOrder` у V и без.
4. Для каждого варианта: `scutil --dns` (резолверы, порт, порядок), `dscacheutil -q host -a name` для `www.example.com`, `z0001.spike.test`, `z0500.spike.test`, `a.b.z0250.spike.test`, `example.org` — какой сервер ответил (адрес ответа + лог `dnsspike`), время первого ответа после `set`.
5. Без V — имя вне зон идёт исходным DNS VM.
6. `dnsspike` W остановлен — что с именами зон (таймаут, NXDOMAIN, уход к V/исходному) и как быстро.
7. Масштаб: 2000 зон — `scutil --dns` и время применения.
8. `ServerPort` без `ServerAddresses` с портом в адресе (`127.0.0.1.5354`) — работает ли запасной вид.

Отвечает на: работает ли `ServerPort` у supplemental-резолвера; выигрывает ли конкретная зона у `[""]` чужого сервиса независимо от порядка; переварит ли mDNSResponder сотни зон; что при мёртвом резолвере.

### 2. `dsmemberutil` (`wgp-check-dns`, агент)

1. Пользователи `u1`, `u2` (`sysadminctl -addUser`), группы `wgp-a`, `wgp-b`; `u1` ∈ `wgp-a`, `wgp-a` ∈ `wgp-b` (вложенная, `dseditgroup -o edit -a wgp-a -t group wgp-b`).
2. `dsmemberutil checkmembership -u <uid> -G <group>` и `-g <gid>`: `u1`/`wgp-b` (вложенная), `u2`/`wgp-b`, `admin`/`admin`, root/`admin`, несуществующий uid (`70000`), несуществующая группа, удалённый пользователь (uid остался в процессе). Вывод и код выхода каждого.
3. Время: 100 вызовов подряд, холодный первый и тёплые; после изменения членства — сколько до нового ответа (кеш `opendirectoryd`, `dsmemberutil flushcache`).
4. Без root: тот же вызов от `admin` и от `u2` — работает ли (демон вызывает от root, но для `wgplex check` важно).

### 3. `SMAppService.mainApp` с ad-hoc подписью (`wgp-check-gui`, агент + пользователь)

Помощник: `SMSpike.app` — Swift, `swiftc` на хосте, bundle id `io.github.mrfokin.wgplex.smspike`, `LSUIElement`; аргументы `--register`, `--unregister`, `--status` пишут результат (`status`, ошибку) в `/tmp/smspike.log`; при запуске без аргументов — дописывает строку «launched <версия> <время>». Две сборки, `1` и `2` (разный cdhash), ad-hoc `codesign --sign -`.

1. Агент: сборка `1` в `/Applications`, `open -a SMSpike --args --register` в GUI-сессии `admin` (VM входит сама), `--status`, `sfltool dumpbtm` (sudo, WF S9).
2. Пользователь: что показала система (уведомление «Login item added»), запись в «Системные настройки → Основные → Объекты входа».
3. Агент: перезагрузка VM — приложение запустилось само (лог)?
4. Агент: замена на сборку `2` (копия поверх, как при обновлении из `.dmg`), `--status` без повторной регистрации, перезагрузка — запустилась ли `2`; `sfltool dumpbtm` — запись та же или новая.
5. Пользователь: «Объекты входа» после обновления — одна запись или две, включена ли.
6. `--unregister` — запись исчезла.

### 4. Неподписанный cask из стороннего tap (`wgp-check-gui`, агент + пользователь)

Помощник: `SMSpike-1.dmg`, `SMSpike-2.dmg` (`hdiutil create`), раздаются с хоста `python3 -m http.server` на адресе хоста в LAN; tap — `brew tap-new mrfokin/spike` в VM (локальный git, без публикации), cask `smspike` с `url "http://<host>:<port>/SMSpike-#{version}.dmg"`, `sha256`, `app "SMSpike.app"`.

1. Пользователь: Gatekeeper включён (`sudo spctl --master-enable` делает агент, «Разрешать программы из» — в настройках, WF S2).
2. Агент: `brew install --cask mrfokin/spike/smspike` — ставится ли, предупреждения, `xattr` (карантин) на `.app`, `spctl --assess`.
3. Пользователь: первый запуск из Finder — блокировка, текст, «Всё равно открыть».
4. Агент: поднять версию в cask, `brew upgrade --cask smspike` — ставится ли, карантин на новой копии. Пользователь: запускается ли без повторного разрешения.
5. Агент: `brew audit`/`brew style` cask'а — что Homebrew 7 говорит про отсутствие подписи (нужно ли что-то в cask, например `caveats`).
6. Чистые факты для README и design 17.1.

## Файлы

```
scripts/vm.sh            новый
docs/plans/m0-spike.md   этот план
docs/design.md           правки по фактам (шаг 5, после согласования)
```

## Шаги

1. План утверждён, коммит плана в `m0-spike`.
2. `go-dev` (worktree): `scripts/vm.sh` по разделу выше, `bash -n`, коммит. `reviewer` — дифф, исправления.
3. Оркестратор: `vm.sh base` (в фоне, долго — скачивание brew); затем `vm.sh up smoke`: SSH ключом, вход паролем отклонён, `sudo -n true`, `brew --version`, `tart exec`, IP из LAN хоста (bridged), `curl https://example.com`, DNS VM — не DNS хоста; `vm.sh down smoke`. Если bridged не работает — `--nat` по умолчанию, факт в план. Пользователь: общий буфер обмена с окном VM (`vm.sh up smoke --gui`).
4. Параллельно два агента `general-purpose`:
   - А — проверки 1–2 в `wgp-check-dns`, отчёт с выводом команд;
   - Б — помощники 3–4, автоматические шаги в `wgp-check-gui`; шаги пользователя оркестратор передаёт пользователю по одному.
   VM удаляются после проверок.
5. «Факты spike» в план; предложения правок `design.md` (8, 5, 17.1, 17.5, 20) — пользователю, после согласования — правка в ветке.
6. `reviewer` — дифф ветки (план, `vm.sh`, `design.md`); слияние в `master` по CLAUDE.md, «Git».

## Ручные шаги (пользователь)

- Шаг 3: буфер обмена в окне VM.
- Проверка 3: уведомление и «Объекты входа» после регистрации и после обновления.
- Проверка 4: «Разрешать программы из», первый запуск и «Всё равно открыть», запуск после `upgrade`.

## Готово, когда

- `wgp-base` собран, `vm.sh` поднимает и удаляет клоны, SSH только ключом, сеть — bridged (или решение про NAT записано).
- По каждой проверке 1–4 — факты с выводом команд в «Факты spike» и ответ на вопрос из design 20.
- Правки `design.md` по фактам согласованы и внесены (или зафиксировано, что не нужны).
- `wgp-check-*` удалены, в `~/.tart` — только `wgp-base` и прежние образы.

## Вопросы пользователю

1. Решения 1–6 — приняты (2026-10-20).

## Факты spike

(заполняется по ходу)

## Ход работы

- [x] План и решения 1–6 утверждены (2026-10-20)
- [ ] Шаг 2 — `scripts/vm.sh`, ревью
