## C4 Level 3 — Component (чернетка v0.1): контейнер «Вузол» (FastAPI, Python 3, asyncio)

> Зміст чернетки збережено без змін (вузли, зв'язки, підписи); для коректного відображення в Obsidian синтаксис `C4*` замінено на `flowchart`.

```mermaid
flowchart TB
    spa(["<b>SPA</b><br/>React<br/>Клієнт"])
    peer(["<b>Інший вузол</b><br/>FastAPI<br/>Peer"])
    subgraph node["Вузол"]
        direction TB
        docapi["<b>DocumentsController</b><br/>FastAPI router<br/>POST/GET documents"]
        chainapi["<b>ChainController</b><br/>FastAPI router<br/>GET chain, node info"]
        wsblocks["<b>WsBlocksHandler</b><br/>WebSocket<br/>Прийом блоків"]
        wspbft["<b>WsPbftHandler</b><br/>WebSocket<br/>Повідомлення PBFT"]
        mempool["<b>Mempool</b><br/>Python<br/>Черга записів"]
        engine["<b>ConsensusEngine</b><br/>Python<br/>PoW та PBFT"]
        chainstate["<b>ChainState</b><br/>Python<br/>Ланцюг у пам'яті"]
        validator["<b>ChainValidator</b><br/>blockchain_core<br/>Валідація"]
        signer["<b>IssuerSigner</b><br/>cryptography<br/>Підпис записів"]
        repo["<b>ChainStore</b><br/>File<br/>Читання і запис блоків"]
        sync["<b>SyncService</b><br/>httpx<br/>Синхронізація"]
        metrics["<b>MetricsExporter</b><br/>prometheus_client<br/>Метрики"]
    end
    store[("<b>Chain Store</b><br/>File<br/>Ланцюг")]
    spa -->|"Викликає"| docapi
    spa -->|"Викликає"| chainapi
    peer -->|"Надсилає блоки"| wsblocks
    peer -->|"Надсилає повідомлення"| wspbft
    docapi -->|"Підписує"| signer
    docapi -->|"Додає"| mempool
    docapi -->|"Шукає документ"| repo
    chainapi -->|"Читає"| chainstate
    engine -->|"Бере записи"| mempool
    engine -->|"Додає блок"| chainstate
    wsblocks -->|"Додає блок"| chainstate
    wspbft -->|"Передає"| engine
    chainstate -->|"Зберігає"| repo
    sync -->|"Замінює ланцюг"| chainstate
    repo -->|"Пише"| store
    engine -->|"Метрики"| metrics
```
