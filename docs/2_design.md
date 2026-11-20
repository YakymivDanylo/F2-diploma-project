# РОЗДІЛ 2. ПРОЄКТУВАННЯ АРХІТЕКТУРИ СИСТЕМИ

Розділ описує архітектуру системи за моделлю C4 (рівні Context, Container, Component) у форматі Diagrams-as-Code (Mermaid) і фіксує ключове архітектурне рішення. Усі діаграми трасуються до вимог [SRS](srs.md) та до рішення [ADR-0001](adr/0001-choice-of-technology.md). Посилання виду `SRS-FUN-NN` ведуть до відповідної вимоги у `srs.md`.

## 2.1 Контекстне та контейнерне моделювання системи (C4 Model)

### 2.1.1 Рівень 1 — System Context

<a id="diagram-level1"></a>

```mermaid
flowchart LR
    issuer(["<b>Емітент</b><br/>Person<br/>Заклад освіти; подає хеш документа"])
    verifier(["<b>Верифікатор</b><br/>Person<br/>Перевіряє автентичність документа"])
    operator(["<b>Оператор вузла</b><br/>Person<br/>Розгортає вузол, моніторить мережу"])
    attacker(["<b>Зловмисник</b><br/>Person_Ext<br/>Модель загроз: Sybil, backdating"])

    sys["<b>Блокчейн-система верифікації документів</b><br/>System<br/>P2P-мережа вузлів-валідаторів (по одному на заклад),<br/>SPA, контур спостережуваності, компонент симуляції атак"]

    issuer -->|"Подає хеш документа<br/>HTTPS / REST, TLS 1.3"| sys
    verifier -->|"Перевіряє документ за хешем і Merkle proof<br/>HTTPS / REST, TLS 1.3"| sys
    operator -->|"Розгортає (docker compose), дивиться дашборд Grafana<br/>docker compose CLI; HTTPS"| sys
    attacker -.->|"Підключає сторонні вузли, підробляє блоки<br/>REST / HTTPS; WebSocket / wss"| sys

    classDef person fill:#dbeafe,stroke:#1d4ed8,color:#0f172a;
    classDef ext fill:#fee2e2,stroke:#b91c1c,color:#0f172a;
    classDef system fill:#d1fae5,stroke:#047857,color:#0f172a;
    class issuer,verifier,operator person;
    class attacker ext;
    class sys system;
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
flowchart TB
    issuer(["<b>Емітент</b><br/>Person"])
    verifier(["<b>Верифікатор</b><br/>Person"])
    operator(["<b>Оператор вузла</b><br/>Person"])
    attacker_actor(["<b>Зловмисник</b><br/>Person_Ext"])

    subgraph compose["docker compose, один хост"]
        direction TB
        spa_host["<b>SPA Host</b><br/>nginx<br/>Статика SPA; CSP"]
        spa["<b>SPA</b><br/>React, TypeScript (браузер)<br/>Хешування, видача, верифікація,<br/>візуалізація, підписка на блоки"]

        subgraph p2p["P2P-мережа валідаторів: по одному вузлу на заклад"]
            direction TB
            mesh(("<b>Повнозв'язна сітка</b><br/>6 пар вузлів<br/>/ws/pbft, /ws/blocks, GET /chain<br/>wss + HTTPS, TLS 1.3"))
            node1["<b>Вузол 1</b> (заклад A)<br/>Python 3, FastAPI, asyncio<br/>REST + WebSocket; PoW або PBFT"]
            node2["<b>Вузол 2</b> (заклад B)<br/>Python 3, FastAPI, asyncio"]
            node3["<b>Вузол 3</b> (заклад C)<br/>Python 3, FastAPI, asyncio"]
            node4["<b>Вузол 4</b> (заклад D)<br/>Python 3, FastAPI, asyncio"]
            vol1[("<b>Том вузла 1</b><br/>ChainStore JSON/SQLite, v2<br/>ключі 0600, знімки")]
            vol2[("<b>Том вузла 2</b>")]
            vol3[("<b>Том вузла 3</b>")]
            vol4[("<b>Том вузла 4</b>")]
            mesh <--> node1
            mesh <--> node2
            mesh <--> node3
            mesh <--> node4
            node1 -->|"Файловий I/O"| vol1
            node2 -->|"Файловий I/O"| vol2
            node3 -->|"Файловий I/O"| vol3
            node4 -->|"Файловий I/O"| vol4
        end

        prometheus["<b>Prometheus</b><br/>Збирає метрики вузлів"]
        grafana["<b>Grafana</b><br/>Провізований дашборд"]
        attacker["<b>Компонент атак</b><br/>Python 3, окремий образ<br/>Sybil та backdating"]
        results[("<b>Результати атак</b><br/>results/attack_runs.csv")]
    end

    issuer -->|"Подає хеш<br/>HTTPS, браузер"| spa
    verifier -->|"Перевіряє документ<br/>HTTPS, браузер"| spa
    spa_host -->|"Віддає статику<br/>HTTPS, TLS 1.3"| spa
    spa -->|"REST/JSON, HTTPS; /ws/blocks, wss<br/>TLS 1.3; вузол обирає користувач"| p2p
    prometheus -->|"GET /metrics<br/>HTTPS, TLS 1.3"| p2p
    grafana -->|"PromQL / HTTPS"| prometheus
    operator -->|"Дашборд<br/>HTTPS"| grafana
    attacker_actor -.->|"Запускає сценарій<br/>docker compose run"| attacker
    attacker -.->|"Sybil; блок із підробленою міткою часу<br/>wss; REST / HTTPS; backdating через спільний том"| p2p
    attacker -->|"Записує результати<br/>файловий I/O"| results

    classDef person fill:#dbeafe,stroke:#1d4ed8,color:#0f172a;
    classDef ext fill:#fee2e2,stroke:#b91c1c,color:#0f172a;
    classDef cont fill:#d1fae5,stroke:#047857,color:#0f172a;
    classDef db fill:#fef3c7,stroke:#b45309,color:#0f172a;
    classDef bus fill:#f3f4f6,stroke:#4b5563,color:#0f172a;
    class issuer,verifier,operator person;
    class attacker_actor,attacker ext;
    class spa_host,spa,node1,node2,node3,node4,prometheus,grafana cont;
    class vol1,vol2,vol3,vol4,results db;
    class mesh bus;
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

**Міжвузлові канали** (на діаграмі повнозв'язна сітка з 6 пар вузлів показана одним вузлом-шиною; кожна пара використовує всі три канали):

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
flowchart TB
    spa(["<b>SPA</b><br/>браузер"])
    peers(["<b>Вузли-піри, компонент атак</b>"])
    prom(["<b>Prometheus</b>"])

    subgraph node["Контейнер «Вузол» (Python 3, FastAPI, asyncio)"]
        direction TB

        subgraph pres["Шар Presentation"]
            direction LR
            mw["<b>Middleware</b><br/>RateLimitMiddleware, GlobalErrorHandler"]
            ctrl["<b>Контролери</b><br/>Documents, Chain, NodeInfo, Peers, Metrics"]
            auth["<b>PeerAuthenticator</b><br/>Guard: підпис NodeKeyPair"]
            og["<b>OriginGuard</b><br/>Guard: Origin"]
            wsb["<b>WsBlocksEndpoint</b><br/>/ws/blocks"]
            wsp["<b>WsPbftEndpoint</b><br/>/ws/pbft"]
        end

        subgraph app["Шар Application"]
            direction TB
            iss["<b>IssuanceService</b>"]
            cq["<b>ChainQueryService</b><br/>лише читання"]
            ing["<b>BlockIngestionService</b><br/>єдина точка входу блоків"]
            cs["<b>ChainState</b><br/>asyncio.Lock"]
            coord["<b>ConsensusCoordinator</b><br/>Strategy"]
            strat["<b>PowStrategy, PbftStrategy</b>"]
            mpf["<b>Mempool, RecordForwarder</b>"]
            syn["<b>SyncService, PeerRegistry</b>"]
            boot["<b>StartupCoordinator</b>"]
            bus["<b>EventBus</b><br/>Observer"]
            snap["<b>SnapshotTask</b>"]
            pRepo{{"<b>ChainRepository</b><br/>порт"}}
            pGw{{"<b>PeerGateway</b><br/>порт"}}
            pMet{{"<b>MetricsPort</b><br/>порт"}}
            pKey{{"<b>KeyProvider</b><br/>порт"}}
        end

        subgraph core["src/blockchain_core: бібліотека без залежності від вузла"]
            lib["<b>ChainValidator, MerkleTree, SignatureService</b>"]
        end

        subgraph infra["Шар Infrastructure"]
            direction LR
            cfg["<b>NodeConfig, KeyResolver</b>"]
            repo["<b>ChainStoreAdapter</b>"]
            gw["<b>PeerGatewayAdapter</b>"]
            metx["<b>PrometheusMetrics</b>"]
            keyst["<b>KeyStore</b>"]
        end
    end

    vol[("<b>Том вузла</b><br/>ланцюг, ключі, знімки")]
    peersOut(["<b>Вузли-піри</b><br/>вихідні з'єднання"])

    spa -->|"REST; /ws/blocks<br/>HTTPS, wss, TLS 1.3"| mw
    peers -->|"REST; WebSocket<br/>HTTPS, wss, TLS 1.3"| mw
    prom -->|"GET /metrics<br/>HTTPS, TLS 1.3"| mw
    mw -->|"ASGI"| ctrl
    mw -->|"ASGI: піри"| auth
    mw -->|"ASGI: браузер"| og
    auth -->|"виклик"| wsb
    auth -->|"виклик"| wsp
    og -->|"лише читання"| wsb

    ctrl -->|"submit_document"| iss
    ctrl -->|"get_document, get_range"| cq
    ctrl -->|"register, list"| syn
    iss -->|"has_hash"| cq
    iss -->|"черга або forward_record"| mpf
    iss -->|"підпис ECDSA"| lib
    iss -->|"ключ емітента"| pKey
    cq -->|"читає"| cs
    cq -->|"Merkle proof"| lib

    wsb -->|"submit_block"| ing
    wsp -->|"asyncio.Queue"| coord
    coord -->|"делегує"| strat
    coord -->|"take_batch"| mpf
    strat -->|"submit_block"| ing
    strat -->|"PBFT-повідомлення"| pGw
    mpf -->|"forward_record"| pGw
    syn -->|"submit_chain"| ing
    syn -->|"fetch_chain"| pGw
    boot -->|"sync"| syn
    boot -->|"load; INIT_CHAIN"| pRepo
    boot -->|"перевірка ключів"| cfg

    ing -->|"ValidatorSet, ключі"| cfg
    ing -->|"validate"| lib
    ing -->|"append"| cs
    ing -->|"BlockAppended"| bus
    bus -->|"метрики"| pMet
    bus -->|"розсилка блоку"| pGw
    cs -->|"persist, load"| pRepo
    snap -->|"копія"| cs
    snap -->|"write_snapshot"| pRepo

    pRepo -.-|"реалізує адаптер"| repo
    pGw -.-|"реалізує адаптер"| gw
    pMet -.-|"реалізує адаптер"| metx
    pKey -.-|"реалізує адаптер"| keyst
    repo -->|"файловий I/O"| vol
    keyst -->|"файловий I/O"| vol
    gw -->|"wss; HTTPS, TLS 1.3"| peersOut

    pRepo ~~~ lib
    pGw ~~~ lib
    pMet ~~~ lib
    pKey ~~~ lib
    lib ~~~ cfg
    lib ~~~ repo
    lib ~~~ gw
    lib ~~~ metx
    lib ~~~ keyst

    classDef ext fill:#e5e7eb,stroke:#374151,color:#0f172a;
    classDef comp fill:#d1fae5,stroke:#047857,color:#0f172a;
    classDef port fill:#ede9fe,stroke:#6d28d9,color:#0f172a;
    classDef lib fill:#fef3c7,stroke:#b45309,color:#0f172a;
    class spa,peers,prom,vol,peersOut ext;
    class pRepo,pGw,pMet,pKey port;
    class lib lib;
```

На діаграмі для читабельності поруч показано близькі за роллю компоненти одним блоком (наприклад, `Middleware` = `RateLimitMiddleware` + `GlobalErrorHandler`, `Контролери` = п'ять роутерів); повний перелік і відповідальності наведено в таблиці нижче. Пунктирна лінія «реалізує адаптер» з'єднує порт шару Application з адаптером шару Infrastructure.

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

### 2.2.1 Реалізація «як побудовано» (Епіки 1–3, станом на 2026-11-20)

Діаграма та таблиця вище описують **цільову** архітектуру (її не змінено). Нижче наведено відповідність цільових компонентів фактичним модулям `src/`, збудованим в Епіках 1–3, і перелік того, що ще заплановано. Назви класів цільової архітектури, яких у коді немає, є логічними ролями, а не іменами типів.

| Цільовий компонент | Фактична реалізація | Примітка |
|---|---|---|
| ConsensusCoordinator, PowStrategy, PbftStrategy | протокол `ConsensusEngine` (`node/consensus/base.py`); `PowEngine` (`consensus/pow.py`); `PbftEngine` (`consensus/pbft/engine.py`) + `view_change.py`, `rounds.py`, `state_store.py`, `forward.py`, `messages.py` | Окремого координатора немає: `CONSENSUS_MODE` обирає один рушій при старті (`node/context.py`). Патерн Strategy зберігається через спільний протокол. |
| BlockIngestionService | `ValidationGateway` (`node/validation_gateway.py`) + `ChainState.append/replace` | Єдина точка перевірки (`screen`, `screen_candidate`) викликає `ChainValidator` ядра; шляхи запису — консенсус, розсилка, синхронізація. |
| ChainState | `ChainState` (`node/chain_state.py`) | Один `asyncio.Lock`; `replace` перевіряє кандидата поза блокуванням, а під блокуванням повторно застосовує правило вибору (`prefer`) до поточного ланцюга: кандидат, який і далі виграє й чий спільний предок ще довіряється, встановлюється попри додавання блоків за цей час (без `prefer` застарілого кандидата відхиляють за лічильником покоління); збереження виконується через `to_thread`. |
| ChainValidator, MerkleTree, SignatureService | `src/blockchain_core` (`validation.py`, `merkle.py`, `signing.py`, `block.py`, `chain.py`, `genesis.py`, `storage/`) | Без змін; бібліотека не імпортує вузол. |
| KeyResolver, NodeConfig | `node/key_resolver.py`, `node/registries.py` (`valid_from`), `node/config.py` | Часозалежний resolver; реєстри статичні. |
| Кеш стану для `GET /node/info` | `ValidityCache` (`node/validity_cache.py`) | Оновлюється лише подіями append/replace. |
| SyncService | `ChainSync` (`node/sync.py`) | Спільний предок + попередня перевірка першого блоку; опитування валідаторів і до 8 інших пірів; backoff на пір (невалідатори 5…300 с, валідатори ≤ 30 с і без backoff за збоїв зв'язку чи узгодженості). Перед запитом ім'я хоста розв'язується й відхиляється, якщо веде на loopback/link-local/unspecified/multicast (`node/netguard.py`). |
| PeerGatewayAdapter | `PeerConnectionManager` (`network/connection_manager.py`) | Одне автентифіковане з'єднання на пір; ліміти рукостискань і не більше 8 одночасних каналів невалідаторів (`MAX_NON_VALIDATOR_LINKS`); цикли набору закриваються для невідомих id, валідатори не рахуються в `max_dialed`. |
| WsBlocksEndpoint, WsPbftEndpoint | `network/ws_blocks.py`, `network/ws_pbft.py` (приймач) | **Окремого ендпоінту `/ws/pbft` немає:** повідомлення PBFT (`pbft_pre_prepare`, `pbft_prepare`, `pbft_commit`, `pbft_view_change`, `pbft_new_view`) і `forward_record`/`forward_record_reply` мультиплексуються за полем `type` на тому самому автентифікованому з'єднанні `/ws/blocks`. |
| PeerAuthenticator | `peers/attestation.py` (підпис реєстрації, domain `node/peer-register/v1`), автентифікація рукостискання в `connection_manager.py`; `node/admission.py` | Підписана реєстрація з доказом володіння ключем для **кожного** піра. |
| PeerRegistry | `peers/registry.py`, `peers/seed_registration.py`, `api/peers.py` | Ліміт 256, TTL невалідаторів, правила адрес, пагінація. |
| IssuanceService | `api/documents.py` (`POST/GET /documents`) + `Mempool` (`node/mempool.py`) | Окремого сервісу немає; оркестрація в обробнику. |
| Mempool, RecordForwarder | `node/mempool.py`; `ForwardService`, `RecordForwarder` (`node/forwarding.py`); `WsRecordForwarder`, `RecordIntake`, `ForwardChannel` (`consensus/pbft/forward.py`) | Виявлення цензури: запис, не фіналізований за три таймаути раунду, ініціює зміну виду. |
| ChainQueryService | `api/chain.py`, `api/documents.py`, `api/node_info.py` (читання через `ChainState`) | Окремого сервісу немає. |
| GlobalErrorHandler | `node/errors.py`; `node/body_limit.py` (413 `payload_too_large`) | Єдиний формат помилок. |
| StartupCoordinator | `node/context.py` (`build_node_context`, `BootError`) і фонове завдання «go-live» у `node/main.py` | Завантаження, перевірка, обмежена початкова синхронізація, потім `serving = true`. |
| EventBus | відсутній | Оновлення `ValidityCache` і розсилка блоків викликаються безпосередньо з `ChainState`/рушіїв. |
| Метрики консенсусу | `node/metrics.py`, `api/metrics.py` (`GET /metrics/consensus`) | JSON-ендпоінт Епіку 3; не Prometheus. |

**Ще не реалізовано (заплановано на пізніші епіки):** підписка SPA на `/ws/blocks` з перевіркою `Origin` (`OriginGuard`; Епік 4), `RateLimitMiddleware` (Слайс 31a), експорт Prometheus `GET /metrics` і `PrometheusMetrics` (Слайс 30), TLS 1.3 (Слайси 32a/32b), `SnapshotTask` і знімки ланцюга (Слайс 33b), Docker-образ і compose-мережа (Слайс 19). Ці компоненти лишаються в цільовій діаграмі вище.

**Зміни, внесені аудитом перед Слайсом 19 (hardening pass H1):** підписана реєстрація пірів з доказом володіння ключем; перевірка спільного предка при розгалуженні замість повної валідації з генезису; ліміти тіл запитів, рукостискань і кадрів; обмеження `MAX_BLOCK_RECORDS = 500`; відмова при старті PBFT без файлу стану; стійкий (sticky) статус Byzantine переживає перезапуск. **Хвиля D (підсумковий перегляд безпеки):** `ChainState.replace` повторно застосовує правило вибору під блокуванням (збіжність PoW-вузла на меншій гілці); повторна реєстрація id з `ValidatorSet` після ротації ключа замінює збережений ключ, `stale_registration` за відставання понад `MAX_FUTURE_SKEW_MS`, а старіша реєстрація в межах цього допуску приймається лише як продовження TTL з тією самою адресою (хвиля E); Byzantine-події дедуплікуються за `(reason, offender)`, а `BYZANTINE_RESET_ON_BOOT=<токен>` (одноразовий дайджест: скидання лише якщо значення дорівнює токену, який вузол пише в WARNING на запуску) — єдиний спосіб зняти липкий статус; backoff валідатора ≤ 30 с; захист вихідних адрес `netguard` (залишковий ризик DNS rebinding — у фабриці TLS-клієнта Епіку 6); `MAX_NON_VALIDATOR_LINKS` = 8; необов'язковий `revoked` у реєстрах (ключ не розв'язується в жодний момент часу, власний відкликаний ключ блокує запуск); WARNING на кожному запуску з `PBFT_ALLOW_MISSING_STATE`; запуск застосовує верхню межу часу до збереженого ланцюга (`timestamp_in_future`). **Хвиля E:** порядок реєстрацій піра (`issued_at` не зменшується); перевірка підписів gossip поза циклом подій; окремі обмежені пули DNS (2 для валідаторів, 4 для інших, таймаут 5 с, кеш 30 с) і для завантаження ланцюга; обмежені лічильники прапорців (LRU 1024) і журнал Byzantine-подій (перша подія порушника, ≤ 4 на порушника, ≤ 32 порушників, ≤ 128 подій); `netguard` відхиляє також 0.0.0.0/8, `::/96` і `fd00:ec2::254`; `MAX_CONCURRENT_HANDSHAKES` = 8; посторінкова перевірка зв'язку/часу суфікса під час завантаження та backoff валідатора 5 с з ескалацією до 30 с після 3 збоїв поспіль; ERROR при запуску з вказівкою на регламент відкликання ключів (`docs/README.md`). Прийнято без змін коду: перший ключ з `valid_from = null` чинний з початку (для ідентичностей, доданих після genesis, задавати `valid_from`); перевірка власної адреси — порівняння рядків (аліас не ловиться, безпечно); на Windows bind-mount показує права 0777, тож Slice 19 має використати іменовані томи або копіювати ключі з `chmod 0600`. Свідомо не змінено: підписи пропозиції блоку та записів не мають domain tag (інакше змінилися б хеші); інші підписані повідомлення мають власні domain tag.

## 2.3 Документування архітектурних рішень (Architecture Decision Records)

| ADR | Назва | Статус |
|---|---|---|
| [ADR-0001](adr/0001-choice-of-technology.md) | Вибір транспорту між вузлами: REST + WebSocket замість брокера повідомлень і gRPC | Approved |

Каталог: [adr/](adr/).
