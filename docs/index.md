# Каталог документации wgplex

Источники правды и производные страницы вики (схема — `procedures/wiki.md` канона).

## Источники правды

| Страница | Summary |
|---|---|
| [design.md](design.md) | Архитектура и поведение: туннели, маршрутизация, DNS, здоровье, права, план этапов 21 |
| [api.md](api.md) | Публичный контракт JSON-RPC демона (на английском): транспорт, методы, ответы, коды ошибок |

## Планы этапов

| Страница | Summary |
|---|---|
| [plans/m0-spike.md](plans/m0-spike.md) | M0: spike среды — образ VM, `scripts/vm.sh`, bridged-сеть, факты для дизайна |
| [plans/m1-port.md](plans/m1-port.md) | M1: механический перенос кода из Wirefork, свои имена и метки, один бинарник |
| [plans/m2-system-mode.md](plans/m2-system-mode.md) | M2: системный режим — конфиг читает демон, `state.json`, `wgplex check`, логи с ротацией |
| [plans/m3-api-naming.md](plans/m3-api-naming.md) | M3 (внеочередной шаг): `tunnel.enable`/`tunnel.disable` вместо `tunnel.setEnabled`, без bool |

## Сырьё

| Каталог | Summary |
|---|---|
| [raw/](raw/) | Неизменяемые raw-источники: статьи, транскрипты, ADR; пока пусто |

## Служебное

- [log.md](log.md) — append-only хронология операций вики (`ingest`, `query`, `lint`).
