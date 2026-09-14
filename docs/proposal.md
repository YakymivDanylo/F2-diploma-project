# Thesis Proposal

**Мови документа:** [Українська](#українська-версія) | [English](#english-version)

---

## Українська версія

**Робоча назва (укр.):** Децентралізована система верифікації документів на основі власної реалізації блокчейн-технології

**Робоча назва (англ.):** Decentralized Document Verification System Based on a Custom Blockchain Implementation

### Актуальність та проблематика

Верифікація автентичності офіційних документів (дипломів, сертифікатів, атестатів) традиційно вимагає прямого звернення до установи-видавця, що є повільним, залежним від доступності реєстратора та вразливим до людського фактора. Централізовані реєстри становлять єдину точку відмови та потенційну ціль для підробки або несанкціонованої ретроактивної фальсифікації записів (backdating).

Складність проблеми полягає не лише в забезпеченні незмінності реєстру, а й у виборі механізму досягнення консенсусу між розподіленими вузлами мережі: різні алгоритми консенсусу відрізняються співвідношенням швидкості підтвердження запису, обчислювальних витрат та стійкості до атак (зокрема Sybil-атаки — створення зловмисником множини фіктивних вузлів для отримання непропорційного впливу на консенсус). Порівняльний аналіз цих компромісів у контексті верифікації документів становить наукову новизну роботи.

### Сформована ідея продукту

Тип системи з архітектурної точки зору — розподілена P2P-мережа блокчейн-вузлів із власною реалізацією структури блокчейну та алгоритмів консенсусу, без використання готових блокчейн-платформ (Ethereum, Hyperledger тощо). Кожен вузол мережі підтримує повну копію ланцюга блоків, обмінюється блоками з іншими вузлами через P2P-протокол та бере участь у досягненні консенсусу щодо наступного блоку. Поверх мережі вузлів розгортається односторінковий веб-застосунок (SPA), що надає інтерфейс для видачі документів установою та їх верифікації будь-яким користувачем за хешем.

### Core Features

1. **Реалізація власної структури блокчейну** — блоки з полями (індекс, мітка часу, хеш попереднього блоку, корінь дерева Меркла, nonce), хешування SHA-256, ланцюжок цілісності (hash-linking) з валідацією під час отримання нового блоку.
2. **Криптографічний підпис документів** — видавець підписує хеш документа приватним ключем (ECDSA/RSA) перед записом у блок; верифікація підпису публічним ключем видавця під час перевірки.
3. **Реалізація та порівняльний аналіз алгоритмів консенсусу** — Proof of Work і PBFT (Practical Byzantine Fault Tolerance), з вимірюванням часу досягнення консенсусу та стійкості до атак за однакового навантаження.
4. **Мережева взаємодія вузлів у P2P-мережі** — розповсюдження нових блоків та синхронізація стану ланцюга між вузлами через з'єднання REST та WebSocket.
5. **Веб-інтерфейс на React** — видача документа (завантаження файлу, обчислення хешу, запис у блокчейн), верифікація за хешем, візуалізація структури ланцюга блоків.
6. **Оркестрація багатовузлової мережі через Docker/docker-compose** — розгортання N незалежних вузлів в окремих контейнерах (не симуляція в одному процесі) для коректної демонстрації розподілених сценаріїв.
7. **Модуль тестування стійкості до атак** — контрольована симуляція Sybil-атаки та спроби ретроактивної фальсифікації запису (backdating), з аналітичною візуалізацією результатів експерименту.

*Необов'язкове розширення поза базовим обсягом:* зберігання файлу документа в IPFS, з фіксацією в блокчейні лише його хешу.

### Інженерні практики розробки (DevSecOps)

Ці практики стосуються процесу розробки й супроводу системи, доповнюють Core Features та підвищують архітектурно-інфраструктурну складність роботи до рівня, очікуваного паспортом спеціальності F2:

- **Конвеєр CI/CD** (GitHub Actions) — автоматичний запуск модульних тестів, статичного аналізу коду та симуляцій атак (Sybil, backdating) під час кожного надсилання змін до репозиторію (push); окрема стадія збірки Docker-образів вузлів.
- **Сканування Docker-образів вузлів засобом Trivy** у CI — виявлення вразливостей залежностей перед розгортанням.
- **Контур спостережуваності (Observability)** — структуровані журнали подій та метрики Prometheus на кожному вузлі (висота ланцюга, кількість з'єднань між вузлами, час досягнення консенсусу), панель моніторингу Grafana для порівняння PoW/PBFT у реальному часі.
- **Architecture Decision Records (ADR)** — фіксація ключових архітектурних рішень (власна реалізація замість готової платформи, вибір PoW та PBFT, свідома відмова від централізованого брокера повідомлень між вузлами).

### Технологічний стек за категоріями

| Категорія | Технології |
|---|---|
| Мови програмування | Python (блокчейн-вузол), JavaScript/TypeScript (React) |
| Архітектурні патерни | Розподілена P2P-мережа, hash-linking, дерево Меркла, консенсус (PoW/PBFT) |
| Фреймворки та бібліотеки | FastAPI, asyncio, `cryptography` (ECDSA/RSA), React |
| Зберігання даних | Власний реєстр блоків лише з додаванням записів (append-only); необов'язково IPFS для файлів документів (у ланцюгу зберігається лише хеш) |
| DevOps-інструменти | Docker, docker-compose, GitHub Actions, Trivy |
| Спостережуваність | Prometheus, Grafana |
| Аналітичний інструментарій дослідження | matplotlib, plotly — для розділу порівняння алгоритмів консенсусу (поза складом основної системи) |

---

## English Version

**Working title (Ukrainian):** Децентралізована система верифікації документів на основі власної реалізації блокчейн-технології

**Working title (English):** Decentralized Document Verification System Based on a Custom Blockchain Implementation

### Relevance and Problem Statement

Verifying the authenticity of official documents (diplomas, certificates, school-leaving certificates) traditionally requires direct contact with the issuing institution. This process is slow, depends on the availability of the registrar, and is vulnerable to human error. Centralized registries are a single point of failure and a potential target for forgery or unauthorized retroactive falsification of records (backdating).

The complexity of the problem lies not only in guaranteeing registry immutability but also in selecting a mechanism for reaching consensus among distributed network nodes. Consensus algorithms differ in their trade-off between record confirmation speed, computational cost, and resistance to attacks, in particular the Sybil attack, in which an adversary creates multiple fictitious nodes to gain disproportionate influence over consensus. A comparative analysis of these trade-offs in the context of document verification constitutes the scientific novelty of the work.

### Product Concept

From an architectural perspective, the system is a distributed P2P network of blockchain nodes with a custom implementation of the blockchain data structure and consensus algorithms, without the use of existing blockchain platforms (Ethereum, Hyperledger, etc.). Each network node maintains a full copy of the block chain, exchanges blocks with other nodes via a P2P protocol, and participates in reaching consensus on the next block. A single-page web application (SPA) is deployed on top of the node network and provides an interface for issuing documents by an institution and for verifying them by hash by any user.

### Core Features

1. **Custom blockchain data structure** — blocks with fields (index, timestamp, previous block hash, Merkle root, nonce), SHA-256 hashing, and an integrity chain (hash-linking) validated on receipt of each new block.
2. **Cryptographic document signing** — the issuer signs the document hash with a private key (ECDSA/RSA) before it is written to a block; the signature is verified with the issuer's public key during verification.
3. **Implementation and comparative analysis of consensus algorithms** — Proof of Work and PBFT (Practical Byzantine Fault Tolerance), with measurement of consensus time and attack resistance under identical load.
4. **Node communication in the P2P network** — propagation of new blocks and synchronization of chain state between nodes over REST and WebSocket connections.
5. **React web interface** — document issuance (file upload, hash computation, blockchain write), verification by hash, and visualization of the block chain structure.
6. **Multi-node network orchestration with Docker/docker-compose** — deployment of N independent nodes in separate containers (not a single-process simulation) to correctly demonstrate distributed scenarios.
7. **Attack resistance testing module** — controlled simulation of a Sybil attack and of a retroactive record falsification attempt (backdating), with analytical visualization of the experiment results.

*Optional extension beyond the base scope:* storing the document file in IPFS, with only its hash recorded on the blockchain.

### Engineering Practices (DevSecOps)

These practices concern the development and maintenance process of the system. They complement the Core Features and raise the architectural and infrastructure complexity of the work to the level expected by the F2 specialty standard:

- **CI/CD pipeline** (GitHub Actions) — automatic execution of unit tests, static code analysis, and attack simulations (Sybil, backdating) on every push; a separate stage builds the node Docker images.
- **Trivy scanning** of node Docker images in CI — detection of dependency vulnerabilities before deployment.
- **Observability** — structured logs and Prometheus metrics on each node (chain height, number of peer connections, consensus time), and a Grafana dashboard for real-time comparison of PoW and PBFT.
- **Architecture Decision Records (ADR)** — documentation of key architectural decisions (custom implementation instead of an existing platform, choice of PoW and PBFT, deliberate rejection of a centralized message broker between nodes).

### Technology Stack by Category

| Category | Technologies |
|---|---|
| Programming languages | Python (blockchain node), JavaScript/TypeScript (React) |
| Architectural patterns | Distributed P2P network, hash-linking, Merkle tree, consensus (PoW/PBFT) |
| Frameworks and libraries | FastAPI, asyncio, `cryptography` (ECDSA/RSA), React |
| Data storage | Custom append-only block registry; optionally IPFS for document files (only the hash is stored on-chain) |
| DevOps tools | Docker, docker-compose, GitHub Actions, Trivy |
| Observability | Prometheus, Grafana |
| Research analysis tools | matplotlib, plotly — for the consensus algorithm comparison chapter (outside the core system) |

---

*Валідовано через AI-Driven Compliance Check (протокол — `F2_Diploma_Yakymiv_DR/05-AI-Insights.md`): текст очищено від розмовного стилю та доповнено практиками CI/CD, Trivy, Observability та ADR за рекомендаціями аналізу відповідності паспорту спеціальності F2.*
