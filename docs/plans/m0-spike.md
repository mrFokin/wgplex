# M0 — spike

Статус: план утверждён 2026-10-20, идёт реализация. Ветка `m0-spike`.

**Цель:** проверить в VM то, на чём держатся решения дизайна, до переноса кода: точечный захват DNS (design 8), проверку членства через `dsmemberutil` (5), `SMAppService.mainApp` с ad-hoc подписью (17.5), неподписанный cask из стороннего tap (17.1), формулу со службой от root (16.4). Попутно — инструмент VM для всех следующих этапов: образ `wgp-base` и `scripts/vm.sh`.

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
3. Сервис V (другой UUID): `ServerAddresses = [127.0.0.1]` (порт 53), `SupplementalMatchDomains = [""]`; варианты — V до W и после W, с `SupplementalMatchOrders` у V и без.
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

### 5. Формула со службой от root (`wgp-check-brew`, агент)

Добавлена по ревью дизайна (2026-10-20): design 3, 16.4 — `service do … require_root true`, `sudo brew services start wgplex`, пути в prefix владельца.

Помощник: `svcspike` — Go, universal не нужен (`arm64`), версии `0.1.0` и `0.2.0`: при старте пишет в stderr и stdout строку с версией, `id`, `os.Args`; затем раз в 10 с — строку в файл `<prefix>/var/svcspike/beat.log` (создаёт каталог, как демон — `var/wgplex`, `var/log/wgplex`); в лог по пути (`<prefix>/var/log/svcspike/svcspike.log`) переключается только по флагу `-dup2` — для сравнения. Архив `svcspike-X.Y.Z.tar.gz`, локальный tap в VM (`brew tap-new mrfokin/spike`), формула `svcspike` с `url "file:///…"`, `bin.install`, `service do`: `run [opt_bin/"svcspike"]`, `require_root true`, `keep_alive true`, без `log_path`/`error_log_path`; `post_install` создаёт `etc/svcspike` (`0700`) с файлом (`0600`), как шаблон design 10.3.

1. `brew install svcspike` от `admin` — владельцы и права: `Cellar/svcspike`, `opt/svcspike`, `etc/svcspike`, `var`, `var/log`, `var/run`, `var/homebrew/linked`, `Library/LaunchDaemons`? (снимок `ls -la`/`stat` по prefix до и после каждой команды; дифф владельцев — главное).
2. `sudo brew services start svcspike` — вывод и предупреждения brew; где plist (`/Library/LaunchDaemons/homebrew.mxcl.svcspike.plist`), его содержимое (`StandardErrorPath`?), `launchctl print system/homebrew.mxcl.svcspike`; кто стал владельцем каких путей в prefix (известно: brew services под sudo меняет владельца на root — проверить, каких именно); куда ушли stderr/stdout первой строки (без `error_log_path` — `/dev/null`?).
3. От `admin` без sudo: `brew services list`, `brew services info svcspike`, `brew services restart svcspike` — что видит и что делает.
4. Поднять версию в формуле, `brew upgrade svcspike` от `admin` — проходит ли (права после шага 2), перезапущена ли служба (pid, версия в `beat.log`), на какой путь смотрит plist (`opt` → новая версия?), нужен ли `sudo brew services restart`.
5. `brew uninstall svcspike` от `admin` при работающей службе — что с службой, plist, `etc/svcspike`, `var/svcspike`; затем `sudo brew services stop`/`cleanup` — что требуется для чистого удаления.
6. `brew cleanup` от `admin` после шагов 2–5 — ошибки прав на файлах, ставших root.
7. Сверх: `brew doctor` после всего — что жалуется на root-владельцев.

Отвечает на: ломает ли `sudo brew services` дальнейшие `brew upgrade`/`uninstall`/`cleanup` от пользователя; перезапускается ли служба при `upgrade`; нужен ли демону свой лог-файл с первой строки (stderr до `dup2`); как писать `caveats` и раздел удаления (design 16.4).

### Хост: маршруты с флагом `2`

`netstat -rn` на хосте (2026-10-20): маршрутов с флагом `2` (`RTF_PROTO2`) и `3` нет; `1` (Wirefork, `RTF_PROTO1`) — у 346 из 455 строк (`UHS1`, `US1c`, `UHS1I`, `UGHS1`). Флаг `RTF_PROTO2` на машине свободен.

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

### Образ и сеть (2026-10-20, `vm.sh base`, VM `wgp-check-smoke`)

- B1. **Vanilla-образ:** гостевого агента tart нет; `/etc/sudoers.d/admin-nopasswd` с правами `0640` — `sudo` его принимает, а `visudo -c` отвергает («bad permissions»): общий `visudo -c` в `vm.sh` не делаем, свой файл проверяется `visudo -cf`.
- B2. **sshd в macOS запускается на каждое соединение** и читает конфиг заново; `launchctl kickstart -k system/com.openssh.sshd` делает его недоступным на время («Connection timed out during banner exchange») — перезапуск не нужен. Вход паролем после drop-in: `Permission denied (publickey)`.
- B3. **NAT tart при туннелях хоста не годится.** DNS VM (`192.168.64.1`) идёт через резолвер хоста, захваченный Wirefork: `dig` то отвечает, то нет, системный резолвер VM — таймаут. Трафик к адресам, которые хост маршрутизирует в туннель (`github.com` → `utun9`), из VM не проходит (`Failed to connect … port 443`), публичный DNS этого не лечит. Сборка образа и проверки — в мосте; `--nat` — только при выключенных туннелях хоста.
- B4. **Мост `en0` работает:** VM получает адрес из сети хоста (`192.168.10.19`), DNS и шлюз — роутер `192.168.10.1`, `github.com` — 200. `vm.sh up` от клона до SSH — 13 с; `tart ip --resolver=arp` находит адрес сразу.
- B5. **Гостевой агент** — релиз GitHub `tart-guest-agent` 0.15.0 (LaunchAgent `--run-agent`): `tart exec` работает в VM без окна, вызов — 0,36 с.
- B6. **Homebrew 7.0.10** ставится по SSH без tty (`NONINTERACTIVE=1`), Command Line Tools 27.0 — сам через `softwareupdate`.
- B7. `tart run` из `vm.sh up` (`nohup … &`) переживает конец вызова Bash-инструмента: VM работает дальше.

### Проверка 1 — точечный захват DNS (2026-10-20, `wgp-check-dns`, мост)

Сервис W (wgplex) — `127.0.0.1:5354`, ответ `10.0.0.1`; V («чужой VPN», `[""]`) — `127.0.0.1:53`, ответ `10.0.0.2`. Помощники — scratchpad `m0-spike/dns/` (`dnsspike`, `sckeybin` — cgo `SCDynamicStoreSetValue` из plist, `mbrbin`, сценарии `s1…s12.sh`, `g1…g3.sh`).

- D1. **Достаточно ключа `State:/Network/Service/<UUID>/DNS`** — `Setup:` и `State:/Network/Global/DNS` не нужны (схема Wirefork).
- D2. **`scutil` не пишет сотни зон:** `d.add` — не больше 99 значений (100 — `too many arguments`, поле не пишется); строка длиннее ~2 КБ молча обрезается; повторный `d.add` заменяет поле. Через API (`SCDynamicStoreSetValue`, cgo) — 500–3900 зон, запись 10–15 мс. Wirefork пишет через `scutil` (`internal/dns/sysdns.go`).
- D3. **`ServerPort` у supplemental-резолвера работает:** в `scutil --dns` `port : 5354`, запросы A и AAAA приходят на `:5354`; и через API, и через `scutil` (`d.add ServerPort # 5354`).
- D4. **Без `SupplementalMatchDomainsNoSearch = 1` зоны попадают в search list:** 500 зон — 501 search domain, `foo` даёт 502 запроса и резолвится в `10.0.0.1`, каждый сброс кэша — 500 запросов `PTR lb._dns-sd._udp.<зона>`. С ключом — 0 search domains, зоны работают.
- D5. **Конкретная зона выигрывает у `[""]` при любом порядке** (W→V, V→W, у V `SupplementalMatchOrders = [1]`, `[200000]`): зоны и поддомены (`a.b.z0250.spike.test`) → W, остальное → V; `dscacheutil` и `dns-sd -G` одинаково. Побеждает самый длинный суффикс.
- D6. **Ключ — `SupplementalMatchOrders` (массив параллельно доменам)**, `SupplementalMatchOrder` и `SearchOrder` игнорируются. Порядок решает только при одинаковом домене у двух сервисов; более длинный домен чужого сервиса (`www.example.com`) забирает имя у зоны W.
- D7. **Без явного порядка при одинаковом домене победитель случаен:** IPMonitor даёт `100000 + 200·k + i`, k — позиция сервиса в словаре, не порядок публикации и не UUID.
- D8. **Скорость:** 500 зон — первый ответ через 86 мс после записи, замена 500 → 501 — 71 мс; 2000 зон — 450–480 мс, `scutil --dns` — 28 мс; RSS mDNSResponder ~34 МБ, configd ~33–35 МБ.
- D9. **Молчаливый предел — 3900–4000 зон** (имена по 16 символов): ключ в store записан, а DNS-конфигурация системы остаётся прежней, ошибок в логах нет. Похоже на предел размера dnsinfo — зависит от длины имён.
- D10. **Мёртвый резолвер W:** имена зон — `<none>` через 60 с (`dscacheutil`), к V и исходному DNS не уходят; остальные имена работают. Снятие ключа сразу освобождает и зависшие запросы (ответ исходного DNS через 2,1 с при снятии на 2-й секунде), новые — ~44 мс. После перезапуска резолвера — 24 мс.
- D11. `ServerAddresses = [127.0.0.1.5354]` без `ServerPort` — резолвер не создаётся.
- D12. mDNSResponder шлёт на supplemental-резолвер `SVCB _dns.resolver.arpa` (DDR) — резолвер должен отвечать на незнакомые типы, не падая.

### Проверка 2 — `dsmemberutil` (2026-10-20, `wgp-check-dns`)

- G1. **Вложенные группы учитываются:** u1 ∈ wgp-a ∈ wgp-b — `checkmembership -u 502 -G wgp-b` → «user is a member of the group»; root (0) ∈ admin.
- G2. **Код выхода не различает «член» и «не член» (оба 0)** — разбирать stdout. Несуществующий uid или gid — «not a member», 0; несуществующая группа по имени — «Group not found», код 7. Текст английский при любой `LANG`.
- G3. Удалённый пользователь — «not a member», хотя имя осталось в `GroupMembership`.
- G4. **Время:** первый вызов после `flushcache` — 11 мс, тёплый — 6 мс, 100 вызовов — 136 мс (~85 мс — `fork/exec`).
- G5. **Кэш не мешает:** изменение членства (`dseditgroup`, `dscl`) видно с первого вызова.
- G6. Работает без root (admin и обычный пользователь — те же ответы).
- G7. **`mbr_check_membership` (cgo)** — те же ответы, несуществующая группа — `ENOENT` при поиске имени; 0,14–2 мс, без root.

### Проверка 5 — формула со службой от root (2026-10-20, `wgp-check-brew`, Homebrew 7.0.10)

Помощники — scratchpad `m0-spike/brew/` (`svcspike` 0.1.0–0.4.0, шаблоны формулы, `snap.sh`/`sdiff.sh` — снимок и дифф владельцев).

- H1. **Доверие к tap (новое в Homebrew 7):** `brew install mrfokin/spike/svcspike` по полному имени доверяет сам («Trusted formula …», `~/.homebrew/trust.json`); по короткому имени без доверия — «Refusing to load formula … from untrusted tap», код 1. `url "file://…"` с `sha256` ставится без флагов. `tap-new` включает developer mode (выключен `brew developer off`).
- H2. **`brew install` от `admin`:** всё `admin:admin`, `post_install` создаёт `etc/svcspike` `0700` и файл `0600`, но «Calling `post_install` is deprecated! Use `post_install_steps` instead.» `var/log`, `var/run` на чистом prefix нет. В caveats brew сам дописывает `sudo brew services start mrfokin/spike/svcspike`.
- H3. **`sudo brew services start`** — «Warning: Taking root:admin ownership of some svcspike paths» (`chown root:admin` + sticky): `Cellar/…/<ver>/bin`, бинарник, симлинки `opt/svcspike` и `var/homebrew/linked/svcspike`; «This will require manual removal of these paths using `sudo rm` on brew upgrade/reinstall/uninstall». `etc`, `var`, `Cellar/<f>` остаются `admin`.
- H4. **Метка — `sh.brew.<name>`**, plist `/Library/LaunchDaemons/sh.brew.svcspike.plist` (`root:admin 0644`): `KeepAlive`, `RunAtLoad`, `ProgramArguments [/opt/homebrew/opt/svcspike/bin/svcspike]`, без `StandardOutPath`/`StandardErrorPath`/`UserName`. Процесс — root.
- H5. **Без `log_path`/`error_log_path` fd 0–2 — `/dev/null`:** всё до `dup2` теряется. С `log_path` и `error_log_path` на файл лога демона — в plist `StandardOutPath`/`StandardErrorPath`, в файле строки до и после `dup2` по порядку; каталог создаёт `brew services` (`root:admin 0755`).
- H6. **Демон, создающий `var/log/<f>` через `MkdirAll` на чистом prefix, делает `var/log` root** — `admin` больше не может создавать там каталоги, `brew doctor`: «directories are not writable by your user: /opt/homebrew/var/log». Каталоги, созданные формулой (`post_install_steps`), остаются `admin`, root пишет в них файлы.
- H7. **`brew services` от `admin` без sudo:** `list` — `svcspike none root`; `info` — «Running: false»; **`restart` запускает вторую копию как LaunchAgent пользователя** (`~/Library/LaunchAgents`, «Warning: `svcspike` must be run as root to start at system startup!», код 0) рядом с работающей службой root; `stop` останавливает только эту копию.
- H8. **`brew upgrade` от `admin` при работающей службе:** код 0, «Warning: Permission denied @ apply2files …/0.1.0/bin/svcspike», остаток старой версии (`svcspike 0.1.0 0.2.0`), копится с каждой версией. **Служба не перезапускается** (тот же pid, старая версия); в `upgrade` перезапуска служб нет.
- H9. `sudo brew services restart` — новая версия, снова «Taking root:admin ownership».
- H10. `sudo brew services stop` перед `upgrade` владельцев не возвращает — тот же остаток.
- H11. **`brew uninstall` от `admin` при службе:** «Error: Could not remove svcspike keg! Do so manually: sudo rm -rf …», код 1; служба работает, plist на месте. `sudo brew uninstall` — «Running Homebrew as root is extremely dangerous and no longer supported.»
- H12. `sudo brew services stop` выгружает службу и удаляет plist; формулу после H11 снимает только `sudo rm -rf Cellar/<f> opt/<f>`.
- H13. **`brew cleanup` от `admin` с root-остатками:** «Error: Could not cleanup old kegs! Fix your permissions on: …», код 1 — и в автоматическом cleanup после каждого `upgrade`.
- H14. `brew doctor` на root-владельцев keg не жалуется; после неудачного uninstall — «unlinked kegs»; на `var/log` — только при H6.
- H15. **Обход A:** `sudo chown -R -h ${USER}:admin Cellar/<f> opt/<f> var/homebrew/linked/<f>` перед `upgrade`/`cleanup`/`uninstall` — всё проходит с кодом 0; `sudo brew services restart` снова забирает новую версию в root.
- H16. **Обход B: `sudo brew services start --sudo-service-user=root <f>`** — `UserName root` в plist, владельцев не меняет (`take_root_ownership?` — false), демон — root. `upgrade` от `admin` чистый, одна версия. Опцию нужно передавать при каждом `start`/`restart`: `restart` без неё снова забирает пути в root.
- H17. **`brew uninstall` раньше `services stop`:** формула удалена, процесс работает, после kill launchd — `last exit code = 78: EX_CONFIG`; `uninstall` снимает доверие, и `sudo brew services stop` — «Refusing to load formula … from untrusted tap», `cleanup` — «not managed by `brew services`». Помогает `brew trust --formula …`, затем `stop`.
- H18. **`post_install_steps`** работает и не трогает существующий `etc` при `reinstall`; `write` устарел — `write_file`. Образец: `unless_path_exists "wgplex", base: :etc do mkdir_p …; write_file …; set_permissions … end`, `mkdir_p "log/wgplex", base: :var`, `mkdir_p "wgplex", base: :var`.

## Ход работы

- [x] План и решения 1–6 утверждены (2026-10-20)
- [x] Шаг 2 — `scripts/vm.sh` (767044b), ревью: блокер B1 — `tart clone` чистит OCI-кэш при нехватке места (`TART_NO_AUTO_PRUNE=1`), замечания — штатное выключение перед клоном, таймаут `tart exec`, `vm_running` без `grep -q` под pipefail, `up` с другими флагами — ошибка, подсказка `--nat`; исправлено (8585397). Решения сверх плана: сборка образа в NAT; гостевой агент — из релиза GitHub (в vanilla его нет), LaunchAgent `--run-agent`
- [x] Шаг 3 — `vm.sh base`, проверка сети: образ собран, факты B1–B7; правки `vm.sh` по ходу (оркестратор): без общего `visudo -c` (B1), без `kickstart` sshd (B2), сборка в мосте (B3), `set_vm_dns` для `--nat`. буфер обмена с окном VM работает в обе стороны (пользователь)
- [x] Проверки 1–2 (агент А): факты D1–D12, G1–G7; VM удалена
- [x] Добавлена проверка 5 — формула со службой от root (по ревью дизайна); маршрутов с флагом `2` на хосте нет
- [x] Решения по фактам 1–2 (пользователь, 2026-10-20): ключи DNS — через SystemConfiguration (cgo); членство — `mbr_check_membership` (cgo) вместо `dsmemberutil`; лимит 1000 зон и проверка `dnsinfo` после записи; `SupplementalMatchOrders = 1` для своих зон. Внесено в design 5, 8, 16.2, 18, 20, 21 вместе с `NoSearch` (D4), 60 с при мёртвом резолвере (D10), DDR (D12)
- [x] Проверка 5 (агент В): факты H1–H18; VM удалена
- [x] Решения по фактам 5 (пользователь, 2026-10-20): запуск `sudo brew services start --sudo-service-user=root wgplex`; `log_path`/`error_log_path` на лог демона; каталоги `var/wgplex`, `var/log/wgplex` — формула (`post_install_steps`), демон родителей не создаёт; не от root — выход с кодом 0 и `keep_alive successful_exit: false`; перезапуск после `upgrade` — в caveats. Внесено в design 3, 4.1, 10.3, 15, 16.3, 16.4, 17.2, 21 вместе с меткой `sh.brew.wgplex`, установкой по полному имени (H1) и порядком удаления (H17)
- [ ] Проверки 3–4 (агент Б): автоматические шаги и шаги пользователя 1–5 пройдены, осталось `--unregister`, `brew upgrade --cask`
