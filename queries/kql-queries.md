# Queries KQL — Detecção de Kerberoasting no Elastic

Todas rodam na barra de busca do **Discover**, contra a data view do índice `kerberoasting`.

---

## 1. Query ingênua (demonstra o problema)

```
EventID: 4769 and EncryptionTypeName: "RC4-HMAC"
```

Traz praticamente todo o dataset (159 eventos). Serve para mostrar por que "detectar RC4" sozinho não basta.

---

## 2. Query de detecção (assinatura)

```
EventID: 4769 and EncryptionTypeName: "RC4-HMAC" and not ServiceName: krbtgt* and not ServiceName: *$ and Status: "0x0"
```

| Cláusula | Função |
|---|---|
| `EventID: 4769` | Somente pedidos de ticket de serviço (TGS) |
| `EncryptionTypeName: "RC4-HMAC"` | Somente o downgrade de criptografia suspeito |
| `not ServiceName: krbtgt*` | Remove o ruído estrutural da conta krbtgt |
| `not ServiceName: *$` | Remove contas de máquina |
| `Status: "0x0"` | Somente requisições bem-sucedidas |

Reduz de 159 para 50 neste dataset.

**Limitação conhecida:** o filtro por nome não pega variações fora de ordem (`kr1btgt`, `krbt2gt`), que neste dataset representam os 50 restantes. Ver a query comportamental abaixo.

---

## 3. Detecção comportamental (a evoluir — ver próximo ciclo)

A ideia: em vez de filtrar por nome de conta, detectar o **padrão de volume** — uma mesma origem (`IpAddress`) pedindo tickets RC4 para muitas contas distintas num intervalo curto. Essa abordagem não depende do nome da conta e portanto não tem o ponto cego da query 2.

> A ser implementada com uma agregação por `IpAddress` + contagem distinta de `ServiceName`. Documentada no próximo commit.
