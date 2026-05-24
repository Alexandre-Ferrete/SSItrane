# Relatório Técnico — SSItrane
## Sistema de Mensagens P2P com Cifra de Ponta-a-Ponta

**Unidade Curricular:** Segurança em Sistemas Informáticos
**Ano lectivo:** 2025/2026

---

## 1. Introdução

O SSItrane é um sistema de mensagens seguro com arquitectura híbrida cliente-servidor/P2P. O servidor actua como directório de utilizadores, autoridade certificadora (CA) e repositório de mensagens offline; toda a comunicação de conteúdo é cifrada de ponta-a-ponta — o servidor nunca tem acesso ao plaintext das mensagens trocadas entre clientes.

Este relatório justifica as escolhas arquitecturais e criptográficas tomadas, apresentando os critérios de selecção, as alternativas consideradas e os compromissos (trade-offs) inerentes.

---

## 2. Modelo Arquitectural

### 2.1 Porquê arquitectura híbrida (e não puramente P2P ou puramente cliente-servidor)?

Uma arquitectura **puramente P2P** (ex: BitTorrent, I2P) elimina o servidor central, mas coloca problemas sérios para um sistema de mensagens:

- Descoberta de peers requer uma DHT ou tracker público — complexidade fora do âmbito do projecto
- Entrega de mensagens para utilizadores offline é não-trivial sem servidor intermediário
- Gestão de identidade e certificados exige algum ponto de confiança

Uma arquitectura **puramente cliente-servidor** (ex: servidores XMPP tradicionais) simplifica tudo, mas o servidor tem acesso ao conteúdo das mensagens — viola a E2EE por definição.

A **arquitectura híbrida** resolve o compromisso:

| Responsabilidade | Onde fica |
|---|---|
| Directório de utilizadores online | Servidor (sem conteúdo) |
| Emissão de certificados (CA) | Servidor (confiança centralizada) |
| Armazenamento de mensagens offline | Servidor (só ciphertext) |
| Troca de mensagens em tempo real | Directo P2P (E2EE completa) |

O servidor conhece **metadados** (quem fala com quem, quando) mas **nunca o conteúdo**. Esta é uma limitação conhecida e aceite no modelo de ameaças (ver secção 3).

### 2.2 Protocolo de transporte

Optou-se por **TCP raw com framing próprio** (cabeçalho de 4 bytes big-endian indicando o comprimento da mensagem) em vez de TLS ou HTTP/WebSocket. A justificação é dupla:

1. **Pedagógica** — implementar o protocolo de segurança manualmente permite compreender cada primitiva em vez de delegar numa biblioteca de TLS opaca
2. **Controlo total** — o protocolo de ratchet e a gestão de chaves são implementados explicitamente, tornando as propriedades de segurança auditáveis linha a linha

---

## 3. Modelo de Ameaças

O sistema foi desenhado para resistir às seguintes ameaças:

| Ameaça | Mitigação |
|---|---|
| Escuta passiva na rede (eavesdropping) | AES-256-GCM em todas as ligações |
| Atacante activo man-in-the-middle | Verificação de certificados X.509 contra CA pinned |
| Servidor comprometido lê mensagens | E2EE: servidor só vê ciphertext |
| Replay de mensagens antigas | Nonces únicos em cada operação AES-GCM |
| Adulteração de mensagens | Tag de autenticação GCM detecta qualquer modificação |
| Comprometimento de chave passada (forward secrecy) | Ratchet de chaves por mensagem (hash ratchet C-S, salt ratchet P2P) |
| Impersonation de utilizador | Ed25519 + certificado assinado pela CA do servidor |
| Brute-force de passwords | PBKDF2-SHA256 com 480 000 iterações |

**Ameaças fora do modelo (limitações aceites):**
- **Análise de metadados:** o servidor sabe quem está online e quem iniciou ligação a quem
- **Compromisso da máquina cliente:** chaves em RAM não estão em enclaves seguros (TPM/SGX)
- **Post-compromise security:** o ratchet P2P usa salts, não troca DH — não recupera PCS completa

---

## 4. Escolha dos Algoritmos Criptográficos

### 4.1 Ed25519 — Assinaturas Digitais

**Para quê:** assinar chaves efémeras no handshake, emitir certificados X.509, verificar identidade de peers P2P.

**Porquê Ed25519 e não RSA-2048 ou ECDSA (P-256)?**

| Critério | RSA-2048 | ECDSA P-256 | **Ed25519** |
|---|---|---|---|
| Tamanho da chave | 2048 bits | 256 bits | 256 bits |
| Tamanho da assinatura | 256 bytes | ~71 bytes | **64 bytes** |
| Velocidade de verificação | Lenta | Moderada | **Muito rápida** |
| Resistência a ataques de canal lateral | Fraca (RSA CRT) | Problemática (nonce reuse) | **Forte (determinístico)** |
| Segurança pós-Snowden | Suspeito (NSA NIST) | Curvas NIST controversas | **Curva de Bernstein, auditada** |

O ponto crítico do ECDSA é que **requer um nonce aleatório por assinatura** (`k`). Se esse nonce for reutilizado ou previsível (como aconteceu com a PlayStation 3 em 2010), a chave privada é recuperável imediatamente. O Ed25519 é **determinístico** — a assinatura é derivada da mensagem e da chave privada via hash, eliminando esta classe de vulnerabilidade completamente.

A resistência a ataques de canal lateral é outra razão decisiva: a implementação da curva Curve25519 foi especificamente desenhada para execução em tempo constante, dificultando ataques de timing.

### 4.2 X25519 — Troca de Chaves ECDH

**Para quê:** estabelecer segredo partilhado no handshake cliente-servidor e nas ligações P2P, sem transmitir chaves simétricas pela rede.

**Porquê X25519 e não DH clássico ou ECDH P-256?**

O Diffie-Hellman clássico requer parâmetros de grupo muito grandes (2048+ bits) para segurança equivalente, tornando-o lento e com assinaturas grandes. As curvas NIST (P-256, P-384) partilham a controvérsia sobre a escolha dos parâmetros (suspeita de backdoor introduzida pela NSA via NIST), embora não haja prova concreta.

A Curve25519 foi desenhada por Daniel Bernstein com **critérios completamente públicos e verificáveis**, sem constantes "mágicas" sem justificação. A sua implementação em tempo constante é mais fácil de fazer correctamente do que P-256, reduzindo o risco de vulnerabilidades na biblioteca.

Outra propriedade importante: X25519 utiliza **chaves efémeras por sessão** (Ephemeral Diffie-Hellman). Isto significa que mesmo que a chave de longa duração do servidor seja comprometida no futuro, as sessões passadas não são descriptografáveis — propriedade chamada **forward secrecy**.

### 4.3 AES-256-GCM — Cifra Simétrica Autenticada

**Para quê:** cifrar o conteúdo de todas as mensagens (canal C-S, canal P2P, mensagens offline).

**Porquê AES-256-GCM e não AES-CBC, ChaCha20-Poly1305 ou AES-128-GCM?**

O requisito fundamental é **cifra autenticada (AEAD)** — não basta cifrar, é necessário garantir integridade. AES-CBC sem MAC é vulnerável a padding oracle attacks (como demonstrado pelo BEAST e POODLE no TLS). A tag de autenticação do GCM detecta qualquer adulteração do ciphertext antes de o desencriptar.

**AES-256-GCM vs AES-128-GCM:** AES-128 oferece segurança suficiente para os próximos 20+ anos contra ataques clássicos. Escolheu-se AES-256 por duas razões: (1) o overhead de performance é negligenciável em hardware moderno com AES-NI; (2) AES-256 oferece margem extra contra avanços em computação quântica (o algoritmo de Grover reduz a segurança efectiva para metade dos bits, deixando AES-128 com 64 bits de segurança — insuficiente a longo prazo, enquanto AES-256 ficaria com 128 bits).

**AES-256-GCM vs ChaCha20-Poly1305:** ChaCha20-Poly1305 é uma alternativa legítima e preferível em dispositivos sem AES-NI (ARM de baixo custo, microcontroladores). Em desktop/server com AES-NI, AES-256-GCM é tipicamente mais rápido. Como o projecto corre em desktop (Linux/Windows), AES-256-GCM é a escolha natural.

**Requisito de unicidade do nonce:** o GCM é seguro apenas se o mesmo nonce nunca for reutilizado com a mesma chave. O ratchet (ver 4.4) resolve isto estruturalmente — a chave muda a cada mensagem, tornando a reutilização de nonce impossível entre mensagens diferentes.

### 4.4 HKDF-SHA256 — Derivação de Chaves

**Para quê:** derivar chaves direccionais (tx/rx) a partir do segredo partilhado ECDH, e avançar o ratchet após cada mensagem.

**Porquê HKDF e não SHA256 simples ou PBKDF2?**

A derivação directa com `SHA256(shared_secret)` tem um problema: o output da função hash pode ter vieses ou correlações com o input. O HKDF (RFC 5869) segue uma construção de dois passos:

1. **Extract:** combina o segredo com um salt para produzir uma pseudorandom key (PRK) com distribuição uniforme
2. **Expand:** estende a PRK para o comprimento necessário usando um `info` contextual

O `info` contextual é fundamental: `b"ServerToClient"` e `b"ClientToServer"` derivam chaves **diferentes** do mesmo master secret, garantindo que a chave TX do servidor nunca é igual à chave RX. Sem este separador, um bug que usasse a chave errada poderia passar despercebido.

**PBKDF2 não é adequado aqui** porque o seu propósito é tornar a derivação **lenta** (para resistir a brute-force de passwords). Para derivar chaves a partir de um segredo já com alta entropia (shared ECDH secret), a velocidade é desejável — o HKDF é a ferramenta correcta.

### 4.5 PBKDF2-HMAC-SHA256 — Hash de Passwords

**Para quê:** armazenar passwords de utilizadores no servidor de forma que não sejam recuperáveis mesmo com acesso à base de dados.

**Porquê PBKDF2 com 480 000 iterações e não MD5, bcrypt ou Argon2?**

MD5 e SHA256 directos são eliminados por serem funções rápidas — um atacante com a base de dados pode testar milhões de passwords por segundo com GPU.

**PBKDF2 vs bcrypt vs Argon2id:**

| Critério | PBKDF2 | bcrypt | **Argon2id** |
|---|---|---|---|
| Resistência CPU | ✓ (iterações) | ✓ (factor de custo) | ✓ |
| Resistência GPU/ASIC | Fraca | Moderada | **Forte (memória)** |
| Padronização | NIST SP 800-132, RFC 8018 | Não padronizado | **IETF RFC 9106 (2021)** |
| Disponibilidade em `cryptography` | ✓ | Requer `bcrypt` extra | Requer `argon2-cffi` extra |

Argon2id seria a escolha ideal pela resistência a ataques de hardware paralelo (GPU farms), mas requer uma dependência externa. PBKDF2 está disponível na biblioteca `cryptography` já utilizada, e com 480 000 iterações (o valor recomendado pelo OWASP em 2023 para PBKDF2-SHA256) oferece protecção razoável. O valor de 480 000 iterações resulta em ~300ms de tempo de derivação num CPU moderno — suficientemente lento para brute-force, suficientemente rápido para login normal.

---

## 5. Protocolo de Handshake (Canal Cliente-Servidor)

O handshake segue um padrão **Ephemeral-Static (1-RTT)** simplificado, análogo ao TLS 1.3:

```
Servidor                          Cliente
   |                                  |
   |── SERVER_HELLO ─────────────────>|
   |   pub_eph_S, sig(ca_priv, pub_eph_S)
   |                                  |
   |<─────────────────── CLIENT_HELLO ─|
   |         pub_eph_C                |
   |                                  |
   [ECDH: shared = X25519(eph_S_priv, eph_C_pub)]
   [master = HKDF(shared, "ServerClientSession")]
   [tx_S = HKDF(master, "ServerToClient")]
   [rx_S = HKDF(master, "ClientToServer")]
```

**Propriedades garantidas:**

- **Autenticidade do servidor:** o cliente verifica `sig(ca_priv, pub_eph_S)` com a `ca_public.key` que tem localmente (certificate pinning). Um servidor impostador não tem a chave privada da CA e não consegue forjar a assinatura.
- **Forward secrecy:** a chave efémera `eph_S` é gerada de novo para cada sessão e descartada após o handshake. Comprometer a chave de identidade da CA no futuro não permite descriptografar sessões passadas.
- **Chaves direccionais:** `tx` e `rx` são derivadas com `info` diferente, evitando reflexão de mensagens.

---

## 6. Forward Secrecy — Mecanismos de Ratchet

### 6.1 Hash Ratchet (Canal Cliente-Servidor)

Após cada mensagem enviada ou recebida, a chave corrente é actualizada:

```python
self.tx_key = HKDF(SHA256, 32, salt=None, info=b"Ratchet").derive(self.tx_key)
```

Isto é uma **cadeia de hash unidireccional**: conhecer a chave `k_n` não permite recuperar `k_{n-1}`. O comprometimento de uma chave de sessão num instante `t` não expõe as mensagens anteriores a `t`.

Este mecanismo é O(1) em custo por mensagem e não requer troca de material criptográfico adicional — adequado para o canal C-S onde o throughput é relevante.

**Limitação:** não oferece *post-compromise security* — se a chave `k_n` for comprometida, todas as mensagens futuras até ao próximo handshake completo estão em risco. O Signal Protocol resolve isto com um ratchet duplo (Double Ratchet), que combina hash ratchet com trocas DH periódicas. Implementar o Double Ratchet completo estava fora do âmbito deste projecto.

### 6.2 Salt Ratchet (Canal P2P)

A cada ~5 mensagens P2P, ambos os peers contribuem com um salt aleatório de 16 bytes assinado com Ed25519:

```
Peer A → Peer B: salt_A, sig(A_priv, salt_A)
Peer B → Peer A: salt_B, sig(B_priv, salt_B)
nova_chave = HKDF(SHA256, 32, salt=salt_A ⊕ salt_B).derive(chave_actual)
```

A verificação da assinatura garante que o salt não foi injectado por um man-in-the-middle. A combinação dos dois salts por XOR garante que nenhum dos peers pode controlar unilateralmente a nova chave — ambos contribuem com entropia.

---

## 7. Mensagens Offline — ECDH Efémero-Estático

Quando o destinatário está offline, o servidor armazena a mensagem cifrada. O esquema usado é **Ephemeral-Static ECDH**, análogo ao IES (Integrated Encryption Scheme):

```
Remetente:
  eph_priv = X25519.generate()
  eph_pub  = eph_priv.public_key()
  shared   = X25519(eph_priv, dest_static_pub)
  key      = HKDF(shared)
  ciphertext, nonce, tag = AES-256-GCM(key, plaintext)
  → envia ao servidor: {ciphertext, nonce, tag, eph_pub}

Servidor armazena: {ciphertext, nonce, tag, eph_pub}
  (não tem a dest_static_priv → não consegue derivar key)

Destinatário (ao ficar online):
  shared   = X25519(dest_static_priv, eph_pub)
  key      = HKDF(shared)
  plaintext = AES-256-GCM.decrypt(key, ciphertext, nonce, tag)
```

**Propriedade chave:** o servidor armazena o ciphertext e a chave pública efémera, mas **nunca** tem acesso à chave privada estática do destinatário. Não consegue derivar o segredo partilhado e portanto não consegue desencriptar a mensagem. Esta é E2EE genuína mesmo para mensagens offline.

---

## 8. Mensagens de Grupo — TreeKEM

Para grupos com `n` membros, o protocolo usa uma variante do **TreeKEM** (Tree Key Encapsulation Mechanism), base do MLS (Messaging Layer Security, RFC 9420).

A intuição: numa árvore binária com `n` folhas (membros), cada nó interno representa uma chave partilhada pelos seus descendentes. Ao actualizar a chave de um membro, só é necessário re-cifrar ao longo do caminho da folha à raiz — **O(log n)** operações em vez de O(n).

```
       raiz (chave de grupo)
      /                    \
   nó_1                  nó_2
  /    \                /    \
Alice  Bob           Carol  Dave
```

Se Alice fizer ratchet, só os nós {Alice, nó_1, raiz} são actualizados e re-cifrados. Bob recebe apenas a actualização de `nó_1` e consegue derivar a nova raiz. Carol e Dave recebem apenas a actualização de `nó_2` (inalterada).

**Porquê não broadcast da chave cifrada para cada membro individualmente?** Para grupos pequenos a diferença é negligenciável, mas o TreeKEM escala melhor e é a abordagem adoptada pelo IETF como standard moderno (MLS RFC 9420).

---

## 9. Infraestrutura de Chave Pública (PKI)

O servidor actua como **CA auto-assinada** que emite certificados X.509 para cada utilizador registado. O cliente verifica os certificados dos peers comparando com a chave pública da CA que tem guardada localmente (`ca_public.key`).

Este é um modelo de **certificate pinning**: o cliente não confia em CAs externas nem no sistema operativo — só confia na CA específica deste servidor. Isto elimina ataques de CA falsa (como os que afectaram DigiNotar em 2011), mas significa que o compromisso da CA do servidor comprometeria todos os certificados emitidos.

**Porquê X.509 e não um formato de certificado mais simples?** Os certificados X.509 incluem metadados de validade (`not_valid_before`, `not_valid_after`) e permitem usar a biblioteca `cryptography` para verificação standardizada. A alternativa seria um formato personalizado, mais simples, mas mais fácil de implementar incorrectamente.

Os certificados têm validade de **365 dias** — um compromisso entre conveniência (não re-registar frequentemente) e limitar a janela de exposição de um certificado comprometido.

---

## 10. Resumo das Escolhas e Alternativas

| Componente | Escolha | Principal alternativa | Razão da escolha |
|---|---|---|---|
| Assinatura | Ed25519 | ECDSA P-256 | Determinístico, sem risco de nonce reuse |
| Troca de chaves | X25519 ECDH | ECDH P-256 | Curva auditada, implementação em tempo constante |
| Cifra simétrica | AES-256-GCM | ChaCha20-Poly1305 | AES-NI disponível; AEAD nativo |
| Derivação de chaves | HKDF-SHA256 | SHA256 directo | Extracção de entropia + separação por contexto |
| Hash de passwords | PBKDF2-SHA256 (480k) | Argon2id | Sem dependências externas; OWASP-compliant |
| Ratchet C-S | Hash ratchet | Double Ratchet | Simplicidade; Double Ratchet fora do âmbito |
| Ratchet P2P | Salt ratchet | Double Ratchet | Contribuição de ambos os peers; assinado |
| Msgs offline | ECDH efémero-estático | Armazenar em plaintext | Servidor não tem acesso ao conteúdo |
| Chaves de grupo | TreeKEM (variante) | Broadcast individual | O(log n) em vez de O(n) |
| Formato de certificados | X.509 | Formato custom | Standard, verificação por biblioteca |

---

## 11. Conclusão

O SSItrane implementa um sistema de mensagens com **segurança em profundidade**: cada camada tem a sua própria protecção, de forma que o comprometimento de uma camada não elimina as protecções das restantes. As escolhas de algoritmos reflectem o estado da arte em criptografia aplicada — X25519/Ed25519 em vez de RSA/DSA, AEAD em vez de cifra sem autenticação, ratchet em vez de chave de sessão fixa.

As limitações mais significativas são a ausência de **post-compromise security** (resolvida pelo Double Ratchet do Signal Protocol, fora do âmbito do projecto), a **fuga de metadados** ao servidor (quem fala com quem), e o uso de PBKDF2 em vez de Argon2id para resistência a hardware paralelo. Estas são compromissos conscientes de escopo, não falhas de design.
