# РОЗДІЛ 2. ПРОЄКТУВАННЯ АРХІТЕКТУРИ СИСТЕМИ

Розділ описує архітектуру системи за моделлю C4 (рівні Context, Container, Component) у форматі Diagrams-as-Code (Mermaid) і фіксує ключове архітектурне рішення. Усі діаграми трасуються до вимог [SRS](srs.md) та до рішення [ADR-0001](adr/0001-choice-of-technology.md). Посилання виду `SRS-FUN-NN` ведуть до відповідної вимоги у `srs.md`.

## 2.1 Контекстне та контейнерне моделювання системи (C4 Model)

### 2.1.1 Рівень 1 — System Context

<a id="diagram-level1"></a>

```mermaid
C4Context
    title Рівень 1. System Context: система верифікації документів

    Person(issuer, "Емітент", "Заклад освіти; подає хеш документа на видачу")
    Person(verifier, "Верифікатор", "Будь-яка сторона, що перевіряє автентичність документа")
    Person(operator, "Оператор вузла", "Розгортає вузол і моніторить мережу")
    Person_Ext(attacker, "Зловмисник", "Модель загроз: Sybil-атака, backdating")

    System(sys, "Блокчейн-система верифікації документів", "P2P-мережа вузлів-валідаторів (по одному на заклад), SPA, контур спостережуваності, компонент симуляції атак")

    Rel(issuer, sys, "Подає хеш документа на видачу", "HTTPS / REST, TLS 1.3")
    Rel(verifier, sys, "Перевіряє документ за хешем та Merkle proof", "HTTPS / REST, TLS 1.3")
    Rel(operator, sys, "Розгортає (docker compose) і моніторить (дашборд Grafana)", "docker compose CLI; HTTPS")
    Rel(attacker, sys, "Підключає сторонні вузли; змінює або підробляє блоки", "REST / HTTPS; WebSocket / wss")
```

**Опис елементів.**

| Елемент | Тип | Роль | Вимоги |
|---|---|---|---|
| Емітент | Person | Подає хеш документа та метадані; підпис формує вузол закладу | [SRS-FUN-08](srs.md#srs-fun-08), [SRS-FUN-32](srs.md#srs-fun-32) |
| Верифікатор | Person | Перевіряє документ за хешем; доказ Merkle перевіряється локально в браузері | [SRS-FUN-38](srs.md#srs-fun-38), [SRS-FUN-52](srs.md#srs-fun-52) |
| Оператор вузла | Person | Запускає `docker compose up`, переглядає метрики | [SRS-FUN-56](srs.md#srs-fun-56), [SRS-FUN-59](srs.md#srs-fun-59) |
| Зловмисник | Person_Ext | Джерело загроз, які імітує компонент атак | [SRS-FUN-61](srs.md#srs-fun-61), [SRS-FUN-62](srs.md#srs-fun-62) |
| Блокчейн-система | System | Єдина система; зовнішніх програмних систем немає (Prometheus і Grafana входять до складу, [SRS п. 1.2](srs.md#12-зовнішнє-середовище)) | [SRS п. 1.1](srs.md#11-призначення-та-межі-scope) |

### 2.1.2 Рівень 2 — Container

<a id="diagram-level2"></a>

```mermaid
C4Container
    title Рівень 2. Container: розгортання docker compose (n = 4, f = 1)

    Person(issuer, "Емітент", "Заклад освіти")
    Person(verifier, "Верифікатор", "Перевіряє документ")
    Person(operator, "Оператор вузла", "Адміністратор розгортання")
    Person_Ext(attacker_actor, "Зловмисник", "Модель загроз")

    System_Boundary(compose, "docker compose, один хост") {

        Container(spa_host, "SPA Host", "nginx", "Віддає статичні файли SPA; заголовки CSP, X-Content-Type-Options")
        Container(spa, "SPA", "React, TypeScript; виконується в браузері", "Хешування SHA-256 у браузері, видача, верифікація, візуалізація ланцюга; підписка на блоки")

        Boundary(p2p, "P2P-мережа валідаторів: по одному вузлу на заклад") {
            Container(node1, "Вузол 1 (заклад A)", "Python 3, FastAPI, asyncio", "REST + WebSocket; консенсус PoW або PBFT; підпис записів ключем емітента закладу")
            ContainerDb(vol1, "Том вузла 1", "ChainStore: JSON або SQLite, формат v2; ключі 0600; знімки", "Ланцюг, IssuerKeyPair, NodeKeyPair, знімки")
            Container(node2, "Вузол 2 (заклад B)", "Python 3, FastAPI, asyncio", "REST + WebSocket; консенсус PoW або PBFT")
            ContainerDb(vol2, "Том вузла 2", "ChainStore: JSON або SQLite, формат v2; ключі 0600; знімки", "Ланцюг, ключі, знімки")
            Container(node3, "Вузол 3 (заклад C)", "Python 3, FastAPI, asyncio", "REST + WebSocket; консенсус PoW або PBFT")
            ContainerDb(vol3, "Том вузла 3", "ChainStore: JSON або SQLite, формат v2; ключі 0600; знімки", "Ланцюг, ключі, знімки")
            Container(node4, "Вузол 4 (заклад D)", "Python 3, FastAPI, asyncio", "REST + WebSocket; консенсус PoW або PBFT")
            ContainerDb(vol4, "Том вузла 4", "ChainStore: JSON або SQLite, формат v2; ключі 0600; знімки", "Ланцюг, ключі, знімки")
        }

        Container(prometheus, "Prometheus", "Prometheus", "Збирає метрики вузлів")
        Container(grafana, "Grafana", "Grafana", "Провізований дашборд: висота ланцюга, з'єднання, час консенсусу")
        Container(attacker, "Компонент атак", "Python 3; окремий Docker-образ", "Сценарії Sybil та backdating")
        ContainerDb(results, "Результати атак", "CSV-файл у томі", "results/attack_runs.csv")
    }

    Rel(issuer, spa, "Подає хеш документа на видачу", "HTTPS, браузер")
    Rel(verifier, spa, "Перевіряє документ за хешем", "HTTPS, браузер")
    Rel(spa_host, spa, "Віддає статичні файли SPA", "HTTPS, TLS 1.3")
    Rel(spa, node1, "POST /documents, GET /documents/{hash}, GET /chain, GET /node/info; підписка на блоки /ws/blocks", "REST / JSON, HTTPS; WebSocket, wss, TLS 1.3")
    Rel(spa, node2, "Те саме; вузол обирається користувачем", "REST / JSON, HTTPS; WebSocket, wss, TLS 1.3")
    Rel(spa, node3, "Те саме; вузол обирається користувачем", "REST / JSON, HTTPS; WebSocket, wss, TLS 1.3")
    Rel(spa, node4, "Те саме; вузол обирається користувачем", "REST / JSON, HTTPS; WebSocket, wss, TLS 1.3")

    BiRel(node1, node2, "PBFT /ws/pbft; блоки /ws/blocks; синхронізація GET /chain", "wss + HTTPS, TLS 1.3")
    BiRel(node1, node3, "PBFT /ws/pbft; блоки /ws/blocks; синхронізація GET /chain", "wss + HTTPS, TLS 1.3")
    BiRel(node1, node4, "PBFT /ws/pbft; блоки /ws/blocks; синхронізація GET /chain", "wss + HTTPS, TLS 1.3")
    BiRel(node2, node3, "PBFT /ws/pbft; блоки /ws/blocks; синхронізація GET /chain", "wss + HTTPS, TLS 1.3")
    BiRel(node2, node4, "PBFT /ws/pbft; блоки /ws/blocks; синхронізація GET /chain", "wss + HTTPS, TLS 1.3")
    BiRel(node3, node4, "PBFT /ws/pbft; блоки /ws/blocks; синхронізація GET /chain", "wss + HTTPS, TLS 1.3")

    Rel(node1, vol1, "Додає блоки; читає ланцюг і ключі під час старту; пише знімки", "Файловий I/O")
    Rel(node2, vol2, "Додає блоки; читає ланцюг і ключі; пише знімки", "Файловий I/O")
    Rel(node3, vol3, "Додає блоки; читає ланцюг і ключі; пише знімки", "Файловий I/O")
    Rel(node4, vol4, "Додає блоки; читає ланцюг і ключі; пише знімки", "Файловий I/O")

    Rel(prometheus, node1, "Опитує GET /metrics", "HTTPS, TLS 1.3")
    Rel(prometheus, node2, "Опитує GET /metrics", "HTTPS, TLS 1.3")
    Rel(prometheus, node3, "Опитує GET /metrics", "HTTPS, TLS 1.3")
    Rel(prometheus, node4, "Опитує GET /metrics", "HTTPS, TLS 1.3")
    Rel(grafana, prometheus, "Запити метрик", "PromQL / HTTPS")
    Rel(operator, grafana, "Переглядає дашборд", "HTTPS")

    Rel(attacker, node1, "Sybil-підключення; ін'єкція блоку з підробленою міткою часу", "wss; REST / HTTPS")
    Rel(attacker, vol1, "Змінює збережений ланцюг (backdating, варіант а)", "Файловий I/O, спільний том")
    Rel(attacker, results, "Записує результати запусків", "Файловий I/O")
    Rel(attacker_actor, attacker, "Запускає сценарій (у моделі загроз; фактично запускає оператор)", "docker compose run")
```

**Опис контейнерів.**

| Контейнер | Технологія | Призначення | Вимоги |
|---|---|---|---|
| SPA Host | nginx | Віддає статику SPA, виставляє CSP та `X-Content-Type-Options`; єдиний носій вимоги захисту SPA | [SRS-NFR-SEC-09](srs.md#srs-nfr-sec-09) |
| SPA | React, TypeScript (браузер) | SHA-256 файлу в браузері, видача, верифікація, локальна перевірка Merkle proof, візуалізація, вибір вузла; отримує події про нові блоки каналом `/ws/blocks` (лише читання) і може опитувати `GET /documents/{hash}` | [SRS-FUN-49…55](srs.md#srs-fun-49) |
| Вузол 1…4 | Python 3, FastAPI, asyncio | REST API, WebSocket, консенсус PoW/PBFT, mempool, валідація та зберігання ланцюга, експорт метрик. Один вузол — один заклад (`issuer_id` і `node_id` парні); TLS 1.3 завершується в процесі вузла (uvicorn); rate limiter — ASGI-middleware вузла. Кількість вузлів задається конфігурацією (n ∈ {4, 7, 10}) | [SRS-FUN-21…48](srs.md#srs-fun-21), [SRS-FUN-57](srs.md#srs-fun-57) |
| Том вузла | `ChainStore` (бекенди JSON і SQLite, формат версії 2, блокування single-writer) | Приватне сховище вузла: повна копія ланцюга, ключі `IssuerKeyPair` і `NodeKeyPair` (права 0600), знімки в окремому каталозі. Спільного сховища немає: репліка кожного вузла незалежна | [SRS-FUN-19](srs.md#srs-fun-19), [SRS-FUN-60](srs.md#srs-fun-60), [SRS-NFR-SEC-07](srs.md#srs-nfr-sec-07), [SRS-NFR-INF-03](srs.md#srs-nfr-inf-03) |
| Prometheus | Prometheus | Опитує `GET /metrics` усіх вузлів | [SRS-FUN-47](srs.md#srs-fun-47), [SRS-FUN-59](srs.md#srs-fun-59) |
| Grafana | Grafana | Провізований дашборд без ручного налаштування | [SRS-FUN-59](srs.md#srs-fun-59) |
| Компонент атак | Python 3, окремий образ | Сценарії Sybil та backdating (а, б); не входить до образу вузла | [SRS-FUN-61…64](srs.md#srs-fun-61) |
| Результати атак | CSV у томі | `results/attack_runs.csv` | [SRS-FUN-63](srs.md#srs-fun-63) |

**Міжвузлові канали** (на діаграмі кожна пара вузлів з'єднана одним двоспрямованим зв'язком, що об'єднує три канали):

| Канал | Протокол | Призначення | Вимоги |
|---|---|---|---|
| `/ws/pbft` | WebSocket, wss, TLS 1.3 | `pre-prepare`, `prepare`, `commit`, view-change, `forward_record`; повідомлення підписані `NodeKeyPair` | [SRS-FUN-24…27](srs.md#srs-fun-24), [SRS-FUN-37](srs.md#srs-fun-37), [SRS-NFR-SEC-08](srs.md#srs-nfr-sec-08) |
| `/ws/blocks` | WebSocket, wss, TLS 1.3 | Розсилка фіналізованих блоків піру та підписка SPA (лише читання; перевірка `Origin`) | [SRS-FUN-43](srs.md#srs-fun-43) |
| `GET /chain`, `POST /peers/register`, `GET /peers` | REST, HTTPS, TLS 1.3 | Синхронізація ланцюга, реєстр `PeerInfo` | [SRS-FUN-40](srs.md#srs-fun-40), [SRS-FUN-42](srs.md#srs-fun-42), [SRS-FUN-44](srs.md#srs-fun-44) |

**Прийняті архітектурні рішення рівня 2:**

- Централізованого API Gateway, брокера повідомлень, Identity Provider і HSM немає: вони суперечать децентралізації та рішенням [SRS п. 6](srs.md#6-обмеження-припущення-середовище). Транспортне рішення обґрунтовано в [ADR-0001](adr/0001-choice-of-technology.md).
- SPA отримує блоки каналом `WS /ws/blocks` (хук `useBlockStream`), тому вузол перевіряє `Origin` рукостискання та застосовує rate limit до сфери `websocket`; SPA нічого не надсилає каналом, окрім підписки.
- Окремого reverse proxy перед вузлом немає: TLS 1.3, rate limiting і журналювання виконуються в процесі вузла, що узгоджується з відсутністю довіреної сторони між клієнтом і вузлом.
- Джерело сертифікатів — розробницький центр сертифікації, який генерує одноразова службова задача перед стартом (compose init); приватний ключ центру не потрапляє в томи вузлів.
- Генератор навантаження k6 і CI (GitHub Actions) є інструментами верифікації, а не контейнерами системи, і на рівні 2 не показані.

## 2.2 Компонентне моделювання критичного сервісу системи (C4 Component)

Для декомпозиції обрано контейнер **«Вузол»**: він містить консенсус, валідацію ланцюга, мережеву взаємодію та API, тобто основне обчислювальне навантаження системи.

<a id="diagram-level3"></a>

```mermaid
C4Component
    title Рівень 3. Component: контейнер «Вузол» (Python 3, FastAPI, asyncio)

    Container_Ext(spa, "SPA", "React; браузер", "Клієнт REST та підписник /ws/blocks")
    Container_Ext(peers, "Вузли-піри та компонент атак", "FastAPI", "Клієнти wss та HTTPS")
    Container_Ext(prom, "Prometheus", "Prometheus", "Опитування метрик")
    ContainerDb_Ext(vol, "Том вузла", "Файловий журнал; ключі 0600", "Ланцюг, ключі, знімки")

    Container_Boundary(node, "Вузол") {

        Boundary(pres, "Шар Presentation") {
            Component(rl, "RateLimitMiddleware", "ASGI middleware", "100 запитів/60 с на IP; обробляє scope http та websocket; 429 + Retry-After")
            Component(eh, "GlobalErrorHandler", "FastAPI exception handlers", "Єдиний формат помилок; структуроване журналювання з correlation id")
            Component(docc, "DocumentsController", "FastAPI router, Pydantic DTO", "POST /documents, GET /documents/{hash}")
            Component(chainc, "ChainController", "FastAPI router, Pydantic DTO", "GET /chain?from=&to=")
            Component(infoc, "NodeInfoController", "FastAPI router", "GET /node/info; healthcheck")
            Component(peersc, "PeersController", "FastAPI router, Pydantic DTO", "POST /peers/register, GET /peers")
            Component(metc, "MetricsEndpoint", "FastAPI router", "GET /metrics")
            Component(auth, "PeerAuthenticator", "Guard", "Підпис NodeKeyPair з domain tag, належність до ValidatorSet")
            Component(og, "OriginGuard", "Guard", "Перевірка заголовка Origin у рукостисканні /ws/blocks для браузерних клієнтів")
            Component(wsb, "WsBlocksEndpoint", "FastAPI WebSocket", "/ws/blocks: блоки від піров; розсилка підписникам, зокрема SPA (лише читання)")
            Component(wsp, "WsPbftEndpoint", "FastAPI WebSocket", "/ws/pbft, forward_record")
        }

        Boundary(app, "Шар Application") {
            Component(iss, "IssuanceService", "Python", "Перевірка емітента, підпис запису, дублікати, постановка в mempool або пересилання")
            Component(cq, "ChainQueryService", "Python", "Пошук документа, Merkle proof, діапазон блоків, стан вузла (лише читання)")
            Component(ing, "BlockIngestionService", "Python", "Єдина точка входу блоків: валідація, потім додавання; межа майбутньої мітки часу лише для нових блоків")
            Component(boot, "StartupCoordinator", "Python, asyncio", "INIT_CHAIN, перехресна перевірка ключів, синхронізація з піра перед обслуговуванням")
            Component(cs, "ChainState", "Python, asyncio.Lock", "Єдиний власник ланцюга в пам'яті, єдиний запис під блокуванням")
            Component(coord, "ConsensusCoordinator", "Python, Strategy", "Обирає стратегію за конфігурацією; формує блок з mempool")
            Component(pow, "PowStrategy", "Python", "Підбір nonce; difficulty у бітах [1, 256]")
            Component(pbft, "PbftStrategy", "Python", "pre-prepare, prepare, commit, view-change")
            Component(mp, "Mempool", "Python", "Черга записів очікування; відхиляє дублікати")
            Component(fwd, "RecordForwarder", "Python", "Пересилання запису primary з відповіддю за request_id")
            Component(sync, "SyncService", "Python, asyncio", "Отримання відсутніх блоків, розв'язання розгалужень")
            Component(preg, "PeerRegistry", "Python", "PeerInfo: лише розсилка, не кворум")
            Component(bus, "EventBus", "Python, Observer", "Подія BlockAppended")
            Component(snap, "SnapshotTask", "Python, asyncio", "Знімок кожні SNAPSHOT_INTERVAL_MIN хв")
            Component(pRepo, "ChainRepository", "Python Protocol (порт)", "append, load, snapshot")
            Component(pGw, "PeerGateway", "Python Protocol (порт)", "broadcast, send, fetch_chain")
            Component(pMet, "MetricsPort", "Python Protocol (порт)", "observe, render")
            Component(pKey, "KeyProvider", "Python Protocol (порт)", "IssuerKeyPair, NodeKeyPair")
        }

        Boundary(core, "src/blockchain_core: бібліотека без залежності від вузла") {
            Component(val, "ChainValidator", "Python", "Порядок: hash, link, difficulty, merkle, signature, structural, quorum; кворум з ValidatorSet.quorum")
            Component(merkle, "MerkleTree", "Python", "Domain separation 0x00 та 0x01; proof")
            Component(sig, "SignatureService", "Python, cryptography", "ECDSA P-256: підпис і перевірка")
        }

        Boundary(infra, "Шар Infrastructure") {
            Component(cfg, "NodeConfig", "Python", "ValidatorSet, IssuerRegistry, algorithm, expected_difficulty; перевірка при старті")
            Component(kr, "KeyResolver", "Python", "resolve(id, at_timestamp) за ValidatorSet та IssuerRegistry")
            Component(repo, "ChainStoreAdapter", "Python", "ChainStore: бекенди JSON і SQLite, формат v2, блокування single-writer")
            Component(gw, "PeerGatewayAdapter", "websockets, httpx", "Вихідні wss та HTTPS з перепідключенням")
            Component(metx, "PrometheusMetrics", "prometheus_client", "Реєстр метрик без PII")
            Component(keyst, "KeyStore", "Python", "Читання ключів з тому (0600)")
        }
    }

    Rel(spa, rl, "Запити REST", "HTTPS / JSON, TLS 1.3")
    Rel(spa, rl, "Підписка на блоки /ws/blocks", "wss, TLS 1.3")
    Rel(peers, rl, "Підключення WebSocket та REST", "wss; HTTPS, TLS 1.3")
    Rel(prom, rl, "GET /metrics", "HTTPS, TLS 1.3")
    Rel(rl, eh, "Передає запит далі", "ASGI")
    Rel(eh, docc, "Маршрутизує", "ASGI")
    Rel(eh, chainc, "Маршрутизує", "ASGI")
    Rel(eh, infoc, "Маршрутизує", "ASGI")
    Rel(eh, peersc, "Маршрутизує", "ASGI")
    Rel(eh, metc, "Маршрутизує", "ASGI")
    Rel(eh, auth, "Маршрутизує WebSocket піра", "ASGI")
    Rel(eh, og, "Маршрутизує WebSocket клієнта", "ASGI")
    Rel(auth, wsb, "Пропускає автентифіковане повідомлення", "виклик у процесі")
    Rel(auth, wsp, "Пропускає автентифіковане повідомлення", "виклик у процесі")
    Rel(og, wsb, "Пропускає підписку (лише читання)", "виклик у процесі")

    Rel(docc, iss, "submit_document(hash, metadata)", "виклик у процесі")
    Rel(docc, cq, "get_document(hash)", "виклик у процесі")
    Rel(chainc, cq, "get_range(from, to)", "виклик у процесі")
    Rel(infoc, cq, "get_node_info()", "виклик у процесі")
    Rel(peersc, preg, "register(peer), list()", "виклик у процесі")
    Rel(metc, pMet, "render()", "виклик через порт")

    Rel(iss, pKey, "Отримує IssuerKeyPair", "виклик через порт")
    Rel(iss, sig, "Підписує DocumentRecord", "ECDSA P-256")
    Rel(iss, cq, "has_hash(hash): дублікат у ланцюгу", "виклик у процесі")
    Rel(iss, mp, "Ставить запис у чергу (primary або PoW)", "виклик у процесі")
    Rel(iss, fwd, "Пересилає запис primary (не-primary PBFT)", "виклик у процесі")
    Rel(cq, cs, "Читає стан", "інтерфейс лише читання")
    Rel(cq, merkle, "Будує Merkle proof", "виклик бібліотеки")

    Rel(wsb, ing, "submit_block(block)", "виклик у процесі")
    Rel(wsp, coord, "on_message(PBFT-повідомлення)", "asyncio.Queue")
    Rel(coord, pow, "Делегує (algorithm = pow)", "Strategy")
    Rel(coord, pbft, "Делегує (algorithm = pbft)", "Strategy")
    Rel(coord, mp, "take_batch(до 256 записів)", "виклик у процесі")
    Rel(pow, ing, "submit_block(змайнений блок)", "виклик у процесі")
    Rel(pbft, ing, "submit_block(блок із commit_signatures)", "виклик у процесі")
    Rel(pbft, pGw, "Розсилає PBFT-повідомлення", "виклик через порт")
    Rel(fwd, pGw, "forward_record primary", "виклик через порт")
    Rel(sync, pGw, "fetch_chain(from, to)", "виклик через порт")
    Rel(sync, ing, "submit_chain(кандидат)", "виклик у процесі")
    Rel(boot, sync, "Синхронізація перед обслуговуванням", "виклик у процесі")
    Rel(boot, pRepo, "load; allow_fresh лише при INIT_CHAIN", "виклик через порт")
    Rel(boot, kr, "Перехресна перевірка ключів за реєстрами", "виклик у процесі")

    Rel(ing, cfg, "Читає ValidatorSet, expected_difficulty", "параметри, що передаються в бібліотеку")
    Rel(ing, kr, "Отримує resolver ключів", "параметр, що передається в бібліотеку")
    Rel(ing, val, "validate_block / validate_chain", "виклик бібліотеки")
    Rel(ing, cs, "append / replace під блокуванням", "виклик у процесі")
    Rel(ing, bus, "Публікує BlockAppended", "Observer")
    Rel(val, merkle, "Перераховує корінь", "виклик у процесі")
    Rel(val, sig, "Перевіряє підписи", "виклик у процесі")
    Rel(kr, cfg, "Читає реєстри", "виклик у процесі")

    Rel(bus, pMet, "Оновлює метрики", "Observer")
    Rel(bus, pGw, "Розсилає блок підключеним вузлам", "Observer")
    Rel(cs, pRepo, "persist / load", "виклик через порт")
    Rel(snap, cs, "Копія стану під блокуванням", "виклик у процесі")
    Rel(snap, pRepo, "write_snapshot", "виклик через порт")

    Rel(repo, pRepo, "Реалізує", "Python Protocol")
    Rel(gw, pGw, "Реалізує", "Python Protocol")
    Rel(metx, pMet, "Реалізує", "Python Protocol")
    Rel(keyst, pKey, "Реалізує", "Python Protocol")
    Rel(repo, vol, "Додає блоки; читає при старті", "Файловий I/O")
    Rel(keyst, vol, "Читає ключі", "Файловий I/O")
    Rel(gw, peers, "Вихідні wss та HTTPS", "wss; HTTPS, TLS 1.3")
```

**Опис компонентів.**

| Шар | Компонент | Роль, взаємодія, патерн | Вимоги |
|---|---|---|---|
| Presentation | RateLimitMiddleware | Перший елемент конвеєра; ASGI-middleware для `http` і `websocket`; 429 з `Retry-After` | [SRS-NFR-SEC-05](srs.md#srs-nfr-sec-05) |
| Presentation | GlobalErrorHandler | Перетворює доменні виключення на єдиний формат `{"error": {...}}`; журнали JSON без секретів і IP | [SRS-FUN-46](srs.md#srs-fun-46), [SRS-NFR-OBS-01](srs.md#srs-nfr-obs-01), [SRS-NFR-COMP-02](srs.md#srs-nfr-comp-02) |
| Presentation | Контролери (Documents, Chain, NodeInfo, Peers, Metrics) | Лише перетворюють HTTP у виклик сервісу; DTO Pydantic відхиляють зайві поля та надто великі тіла | [SRS-FUN-32…42](srs.md#srs-fun-32), [SRS-NFR-SEC-04](srs.md#srs-nfr-sec-04) |
| Presentation | PeerAuthenticator | Guard перед WebSocket-обробниками піра: підпис `NodeKeyPair` з domain tag, членство у `ValidatorSet` | [SRS-FUN-25](srs.md#srs-fun-25), [SRS-NFR-SEC-08](srs.md#srs-nfr-sec-08) |
| Presentation | OriginGuard | Guard перед `/ws/blocks` для браузерних клієнтів: перевірка `Origin` (CORS не діє на WebSocket); канал для SPA лише для читання | [SRS-FUN-50](srs.md#srs-fun-50) |
| Presentation | WsBlocksEndpoint, WsPbftEndpoint | Приймають автентифіковані повідомлення; не змінюють стан напряму | [SRS-FUN-43](srs.md#srs-fun-43), [SRS-FUN-24](srs.md#srs-fun-24) |
| Application | IssuanceService | Оркестрація видачі: перевірка емітента, підпис, дублікати, mempool або `forward_record` | [SRS-FUN-08](srs.md#srs-fun-08), [SRS-FUN-33](srs.md#srs-fun-33), [SRS-FUN-37](srs.md#srs-fun-37) |
| Application | ChainQueryService | Читальний інтерфейс (ISP): пошук документа, proof, діапазони, стан | [SRS-FUN-38](srs.md#srs-fun-38), [SRS-FUN-40](srs.md#srs-fun-40), [SRS-FUN-41](srs.md#srs-fun-41) |
| Application | BlockIngestionService | Єдиний шлях запису в ланцюг для консенсусу, розсилки та синхронізації; викликає `ChainValidator` до додавання; відхиляє нові блоки з надто далекою майбутньою міткою часу (не застосовується до вже фіналізованих ланцюгів) | [SRS-FUN-45](srs.md#srs-fun-45), [SRS-FUN-44](srs.md#srs-fun-44), [SRS-FUN-65](srs.md#srs-fun-65) |
| Application | ChainState | Єдиний власник ланцюга; запис лише під `asyncio.Lock` (single-writer) | [SRS-FUN-20](srs.md#srs-fun-20) |
| Application | ConsensusCoordinator, PowStrategy, PbftStrategy | Патерн Strategy: третій алгоритм додається без зміни координатора | [SRS-FUN-21…31](srs.md#srs-fun-21) |
| Application | Mempool, RecordForwarder | Черга очікування з відхиленням дублікатів; пересилання primary з відповіддю за `request_id` | [SRS-FUN-33](srs.md#srs-fun-33), [SRS-FUN-37](srs.md#srs-fun-37) |
| Application | StartupCoordinator | Явна ініціалізація (`INIT_CHAIN`), перехресна перевірка ключів, синхронізація з піра перед обслуговуванням | [SRS-FUN-66…68](srs.md#srs-fun-66) |
| Application | SyncService, PeerRegistry | Синхронізація та розв'язання розгалужень; `PeerInfo` не впливає на кворум | [SRS-FUN-44](srs.md#srs-fun-44), [SRS-FUN-26](srs.md#srs-fun-26) |
| Application | EventBus | Observer: подія `BlockAppended` для метрик і розсилки; домен не залежить від Prometheus | [SRS-FUN-43](srs.md#srs-fun-43), [SRS-FUN-47](srs.md#srs-fun-47) |
| Application | SnapshotTask | Копія стану під блокуванням, запис знімка через порт | [SRS-FUN-60](srs.md#srs-fun-60) |
| Application | Порти: ChainRepository, PeerGateway, MetricsPort, KeyProvider | Інверсія залежностей (DIP): сервіси залежать від протоколів, реалізації — в Infrastructure | — |
| Core | ChainValidator, MerkleTree, SignatureService | Бібліотека без імпорту вузла; `ValidatorSet`, `expected_difficulty`, resolver ключів передаються параметрами | [SRS п. 6.1](srs.md#61-обмеження-проєктування), [SRS-FUN-12…18](srs.md#srs-fun-12) |
| Infrastructure | NodeConfig, KeyResolver | Єдине джерело реєстрів; перевірка конфігурації при старті; час-залежний resolver | [SRS-NFR-REL-04](srs.md#srs-nfr-rel-04), [SRS-FUN-10](srs.md#srs-fun-10) |
| Infrastructure | ChainStoreAdapter, KeyStore | `ChainStore` (JSON, SQLite), перевірка форми при завантаженні, ключі з тому з правами 0600 | [SRS-FUN-19](srs.md#srs-fun-19), [SRS-NFR-SEC-07](srs.md#srs-nfr-sec-07) |
| Infrastructure | PeerGatewayAdapter, PrometheusMetrics | Вихідні wss/HTTPS з перепідключенням; реєстр метрик без PII | [SRS-FUN-47](srs.md#srs-fun-47), [SRS-FUN-48](srs.md#srs-fun-48) |

**Інваріанти схеми.**

1. Блок потрапляє в `ChainState` лише через `BlockIngestionService` після `ChainValidator` (три шляхи: консенсус, розсилка, синхронізація).
2. Контролери не мають залежності від сховища; читання проходить через `ChainQueryService`.
3. Залежності спрямовані до портів та до бібліотеки `blockchain_core`; бібліотека не імпортує код вузла.
4. Голоси `commit` підписуються над доменним payload `COMMIT_DOMAIN`, кожен тип повідомлення має власний domain tag; поріг кворуму береться з `ValidatorSet.quorum`.
5. Точки зупинки атак: `RateLimitMiddleware` (флуд), `PeerAuthenticator` (Sybil, підроблені повідомлення), `ChainValidator` (backdating, ін'єкція блоку).

## 2.3 Документування архітектурних рішень (Architecture Decision Records)

| ADR | Назва | Статус |
|---|---|---|
| [ADR-0001](adr/0001-choice-of-technology.md) | Вибір транспорту між вузлами: REST + WebSocket замість брокера повідомлень і gRPC | Approved |

Каталог: [adr/](adr/).
