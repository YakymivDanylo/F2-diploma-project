## C4 Level 1 — System Context (чернетка v0.1)

> Зміст чернетки збережено без змін (вузли, зв'язки, підписи); для коректного відображення в Obsidian синтаксис `C4*` замінено на `flowchart`.

```mermaid
flowchart LR
    issuer(["<b>Емітент</b><br/>Person<br/>Заклад освіти"])
    verifier(["<b>Верифікатор</b><br/>Person<br/>Роботодавець"])
    operator(["<b>Оператор вузла</b><br/>Person<br/>Адміністратор"])
    sys["<b>Блокчейн-система верифікації</b><br/>System<br/>P2P-мережа вузлів"]
    prom["<b>Prometheus/Grafana</b><br/>System_Ext<br/>Метрики"]
    issuer -->|"Видає документи"| sys
    verifier -->|"Перевіряє документи"| sys
    operator -->|"Керує"| sys
    prom -->|"Збирає метрики"| sys
```

## C4 Level 2 — Container (чернетка v0.1)

> Зміст чернетки збережено без змін (вузли, зв'язки, підписи); для коректного відображення в Obsidian синтаксис `C4*` замінено на `flowchart`.

```mermaid
flowchart TB
    issuer(["<b>Емітент</b><br/>Person"])
    verifier(["<b>Верифікатор</b><br/>Person"])
    subgraph b["Система"]
        direction TB
        spa["<b>SPA</b><br/>React<br/>Видача, верифікація"]
        node1["<b>Вузол 1</b><br/>FastAPI<br/>Валідатор"]
        node2["<b>Вузол 2</b><br/>FastAPI<br/>Валідатор"]
        node3["<b>Вузол 3</b><br/>FastAPI<br/>Валідатор"]
        node4["<b>Вузол 4</b><br/>FastAPI<br/>Валідатор"]
        store[("<b>Chain Store</b><br/>JSON<br/>Ланцюг")]
        attacker["<b>Attacker</b><br/>Python<br/>Симуляція атак"]
    end
    prom["<b>Prometheus</b><br/>System_Ext<br/>Метрики"]
    issuer -->|"Використовує"| spa
    verifier -->|"Використовує"| spa
    spa -->|"Надсилає дані"| node1
    node1 -->|"Спілкується"| node2
    node1 -->|"Спілкується"| node3
    node1 -->|"Спілкується"| node4
    node1 -->|"Зберігає"| store
    prom -->|"Збирає метрики"| node1
    attacker -->|"Атакує"| node1
```
