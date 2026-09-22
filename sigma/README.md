# Regra Sigma — notas de implementação

## Por que `EncryptionTypeName: 'RC4-HMAC'` e não `TicketEncryptionType: '0x17'`

A regra Sigma canônica de Kerberoasting usa o campo hex `TicketEncryptionType: '0x17'`. Neste lab, o pipeline de ingestão do Elastic normalizou esse valor para o campo legível `EncryptionTypeName: 'RC4-HMAC'`. Os dois representam a mesma coisa (RC4-HMAC, etype 23).

A regra aqui foi adaptada aos campos **do dataset real** em que foi validada — porque uma regra que não bate com os nomes de campo do seu SIEM não dispara, por mais correta que esteja na teoria. Ao portar para outro ambiente, ajuste o nome do campo conforme o schema local (ECS, raw Windows, etc.).

## O ponto cego conhecido desta regra

O filtro `ServiceName|startswith: 'krbtgt'` remove a conta `krbtgt` e variações que **começam** com essa string (`krbtgt1`, `krbtgt2`). Ele **não** remove variações com letras fora de ordem (`kr1btgt`, `krbt2gt`) — e é exatamente isso que o dataset de teste explora.

Isto é intencional e documentado: a regra por assinatura tem um limite estrutural. A detecção robusta é comportamental (volume de tickets RC4 por origem num intervalo curto), a ser adicionada em `sigma/kerberoasting_behavioral.yml` no próximo ciclo.
