# LR6 — чернетка API-контракту v0.1 (до аудиту)

Інструмент: OpenAPI 3.0 (YAML). Контейнери: SPA → Вузол. Первинний каркас, підготовлений Claude Code до запуску ШІ-Аудитора.

```yaml
openapi: 3.0.3
info:
  title: Document Verification Node API
  version: 0.1.0
paths:
  /documents:
    post:
      summary: Submit document
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                hash:
                  type: string
                metadata:
                  type: object
      responses:
        '202':
          description: Accepted
  /documents/{hash}:
    get:
      summary: Verify document
      parameters:
        - name: hash
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Found
        '404':
          description: Not found
  /chain:
    get:
      summary: Get chain range
      parameters:
        - name: from
          in: query
          schema:
            type: integer
        - name: to
          in: query
          schema:
            type: integer
      responses:
        '200':
          description: Blocks
```
