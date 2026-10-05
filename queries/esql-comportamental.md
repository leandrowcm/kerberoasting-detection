# Detecção comportamental (ES|QL)

Roda no Discover, no modo ES|QL (botão "Query in ES|QL").

```
FROM kerberoasting
| WHERE EventID == 4769 AND EncryptionTypeName == "RC4-HMAC" AND Status == "0x0"
| EVAL janela = DATE_TRUNC(10 minutes, @timestamp)
| STATS pedidos = COUNT(*), contas_distintas = COUNT_DISTINCT(ServiceName), contas = VALUES(ServiceName) BY IpAddress, janela
| WHERE contas_distintas >= 5
| SORT contas_distintas DESC
```

| Linha | O que faz |
|---|---|
| `WHERE` (primeiro) | Filtra eventos: pedidos de ticket 4769 com RC4 que deram certo. Sem nenhuma exclusão por nome de conta |
| `EVAL janela` | Corta o tempo em blocos de 10 minutos |
| `STATS ... BY IpAddress, janela` | Para cada origem em cada bloco, conta pedidos e contas diferentes, e lista quais contas foram |
| `WHERE` (segundo) | Filtra grupos depois da contagem: só passa quem pediu 5 contas diferentes ou mais |

O limite de 5 é um piso, sem teto. A query enxerga só o número final de cada janela, então um teto deixaria passar justamente o ataque mais agressivo.

## Resultado no dataset

1 linha: IP `10.0.1.15`, janela de 2 de março de 2024 às 20:50, 86 pedidos para 25 contas diferentes.

## Limitações conhecidas

- Atacante lento, pedindo menos de 5 contas por janela, fica abaixo do limite.
- Atacante que já sabe qual conta quer e pede só ela gera contagem 1.
- Pedidos feitos com AES não passam pelo filtro de RC4.
