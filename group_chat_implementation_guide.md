# Guia de Implementação — Sistema de Chat em Grupo com TreeKEM

## Contexto e Objetivo

O sistema atual implementa comunicação P2P segura entre dois utilizadores, com Ed25519 (assinaturas), X25519 (ECDH), AES-GCM (cifra simétrica) e HKDF (derivação de chaves). O objetivo é estender este sistema para suportar grupos de chat com **TreeKEM** — a estrutura de árvore binária usada pelo protocolo MLS (RFC 9420) — mantendo o mesmo nível de segurança, Forward Secrecy e E2EE que já existe nas conversas individuais.

A motivação para usar TreeKEM em vez de Sender Keys simples é o custo de rekeying: com Sender Keys, quando um membro entra ou sai, é necessário re-cifrar a GroupKey para **todos** os membros restantes — custo O(n). Com TreeKEM, apenas os nós no **caminho da folha afetada até à raiz** são atualizados — custo O(log n). Para um grupo com 1024 membros, isso significa 10 operações em vez de 1023.

Todos os primitivos criptográficos necessários (X25519, HKDF, AES-GCM, Ed25519) já estão implementados no sistema. A mudança é **arquitetural**, não criptográfica.

---

## Conceito Central — Como Funciona o TreeKEM

### A Árvore

Os membros do grupo são organizados nas **folhas** de uma árvore binária completa. Cada nó interno da árvore tem um par de chaves X25519 (pública + privada). A **GroupKey** (chave simétrica AES-256 usada para cifrar mensagens) é derivada do segredo da **raiz** da árvore via HKDF.

```
              [Root]  ← GroupKey = HKDF(Root.secret, "GroupKey")
             /       \
          [AB]       [CD]
          /  \       /  \
        [A]  [B]  [C]  [D]
        (Alice)(Bob)(Carlos)(Diana)
```

Cada membro conhece:
- A sua própria folha (chave privada X25519 própria)
- O **caminho direto** da sua folha até à raiz (as chaves privadas dos nós intermédios que lhe pertencem)
- O **co-path**: as chaves **públicas** dos nós irmãos ao longo do caminho até à raiz (para poder verificar a árvore mas não derivar os segredos dos outros ramos)

O segredo de cada nó interno é derivado fazendo ECDH entre a chave privada do nó filho esquerdo e a chave pública do nó filho direito (ou vice-versa), e depois passando pelo HKDF. O segredo da raiz resulta deste processo recursivo, e é o mesmo para todos os membros — cada um chega lá pelo seu próprio caminho.

### A Lógica de Derivação de Segredos na Árvore

Para um nó interno qualquer com filhos esquerdo (L) e direito (R):

```
nó.secret = HKDF(ECDH(L.priv, R.pub), info="TreeNode")
           = HKDF(ECDH(R.priv, L.pub), info="TreeNode")  ← propriedade do ECDH
```

Esta propriedade do ECDH (que `ECDH(a.priv, b.pub) == ECDH(b.priv, a.pub)`) é o que permite que membros em ramos diferentes cheguem ao mesmo segredo raiz sem nunca comunicarem diretamente entre si.

A GroupKey usada para cifrar mensagens é então:

```
GroupKey = HKDF(Root.secret, salt=epoch, info="GroupKey", length=32)
```

O `epoch` é um contador inteiro que incrementa a cada Add ou Remove. Garante que GroupKeys de épocas diferentes são sempre distintas, mesmo que o Root.secret seja coincidentemente igual.

---

## Estrutura de Dados — O que Precisa de Existir

### 1. O Conceito de Grupo e Epoch

Um grupo tem:
- Um nome único (identificador)
- Um criador, que é automaticamente o **administrador** do grupo — é o único com permissão para adicionar e remover membros e iniciar operações de rekeying
- Um **epoch** atual (inteiro, começa em 0, incrementa em cada Add/Remove)
- Uma árvore de nós com os seus pares de chaves X25519
- Uma lista de membros nas folhas, com a sua posição (índice) na árvore

O epoch é o mecanismo que garante que cada GroupKey é única e que membros removidos não conseguem derivar GroupKeys futuras mesmo que tenham guardado o Root.secret de um epoch anterior.

### 2. Estado que o Servidor Guarda

O servidor guarda o **estado público** da árvore: as chaves **públicas** de todos os nós. As chaves privadas nunca saem dos clientes. O servidor não consegue derivar nenhum segredo da árvore porque só tem chaves públicas.

Concretamente, o servidor guarda por grupo:
- Os metadados do grupo (nome, epoch atual, número de folhas)
- Para cada nó da árvore: o índice do nó e a sua chave pública X25519 (em formato Raw de 32 bytes)
- Para cada membro: o seu username, o índice da sua folha na árvore, e o **encrypted path** — os segredos dos nós do seu caminho até à raiz, cifrados com a chave pública X25519 do membro

### 3. Estado que Cada Cliente Guarda

Cada cliente guarda apenas:
- O seu índice de folha na árvore
- As chaves privadas X25519 dos nós no seu caminho direto até à raiz (são `log₂(n)` nós)
- As chaves públicas dos nós no seu co-path (os nós irmãos ao longo do caminho)
- A GroupKey atual (derivada do Root.secret) e o epoch correspondente

Isto é muito mais eficiente do que guardar toda a árvore: cada cliente guarda O(log n) chaves privadas e O(log n) chaves públicas.

### 4. Mensagens de Grupo

Uma mensagem de grupo contém:
- O conteúdo cifrado com a GroupKey (AES-GCM → ciphertext + nonce + tag)
- O epoch que indica qual GroupKey foi usada (em vez de key_id, porque o epoch já serve este propósito)
- O sender
- O room_name

O servidor reencaminha a mensagem a todos os membros online. Para membros offline, guarda a mensagem cifrada tal como está — não precisa de a decifrar.

---

## Fluxo Completo — Passo a Passo

### Criação de um Grupo (epoch = 0)

1. Alice envia ao servidor um pedido de criação de grupo com o nome e a lista de membros iniciais (por exemplo, Alice, Bob, Carlos, Diana = 4 membros).

2. O servidor cria o grupo, reserva 4 folhas na árvore (índices 0, 1, 2, 3), e devolve a Alice as chaves X25519 públicas de encriptação de todos os membros (já estão na tabela `user_devices`).

3. O cliente de Alice constrói a árvore localmente:
   - Gera um par X25519 para cada nó interno da árvore (neste caso, 3 nós internos para 4 folhas)
   - As folhas são as chaves X25519 públicas de cada membro (que já existem no sistema)
   - Deriva os segredos dos nós internos recursivamente a partir das folhas, usando ECDH + HKDF
   - Deriva o Root.secret e a GroupKey = HKDF(Root.secret, epoch=0, info="GroupKey")

4. Alice prepara o **KeyPackage** de cada membro — o conjunto de segredos de nós que aquele membro precisa de conhecer para derivar o Root.secret, cifrados com a chave X25519 pública desse membro. Para cada membro M na folha i, Alice cifra (via Ephemeral-Static ECDH, exatamente como no `encrypt_offline`) os segredos dos nós no caminho de i até à raiz.

5. Alice envia ao servidor:
   - As chaves **públicas** de todos os nós internos da árvore (o estado público)
   - Os KeyPackages cifrados para cada membro
   - O epoch = 0

6. O servidor guarda o estado público da árvore e os KeyPackages. Notifica todos os membros online de que foram adicionados ao grupo e entrega-lhes o seu KeyPackage.

7. Cada membro, ao receber o seu KeyPackage, decifra-o com a sua chave X25519 privada, obtém os segredos dos nós do seu caminho, e deriva o Root.secret e a GroupKey. A partir deste momento, todos os membros têm a mesma GroupKey sem que o servidor alguma vez a tenha conhecido.

### Envio de uma Mensagem de Grupo

1. Alice cifra o texto com a GroupKey atual (AES-GCM), obtendo ciphertext + nonce + tag.
2. Alice envia ao servidor: room_name + epoch + sender + ciphertext + nonce + tag.
3. O servidor valida que Alice é membro do grupo e que o epoch corresponde ao epoch atual.
4. O servidor reencaminha a mensagem a todos os membros online.
5. Para membros offline, guarda a mensagem cifrada associada ao epoch.
6. Cada membro decifra com a GroupKey do epoch correspondente.

### Adição de um Novo Membro (epoch → epoch + 1)

Este é o cenário onde o TreeKEM começa a mostrar a sua eficiência. Suponha que o grupo tem Alice (folha 0), Bob (folha 1), Carlos (folha 2), Diana (folha 3), e queremos adicionar o Eduardo (folha 4).

1. O administrador (Alice) envia ao servidor um pedido de adição do Eduardo.
2. O servidor devolve a chave X25519 pública de encriptação do Eduardo e reserva a folha 4 na árvore. A árvore expande de 4 para 8 folhas (árvores binárias completas têm sempre 2^k folhas; as folhas 5, 6, 7 ficam vazias por enquanto).
3. O cliente de Alice atualiza a árvore localmente:
   - Insere a chave pública do Eduardo na folha 4
   - Regenera **apenas** os nós no caminho da folha 4 até à raiz — que são os nós que ficaram "desatualizados" pela inserção
   - Gera novos pares X25519 para esses nós, deriva os novos segredos, e chega a um novo Root.secret
   - Deriva nova GroupKey = HKDF(novo Root.secret, epoch=1, info="GroupKey")
4. Alice prepara:
   - O KeyPackage do Eduardo (os segredos do caminho da folha 4 até à raiz, cifrados para Eduardo)
   - Uma **Update Message** para os membros existentes: apenas os nós que mudaram no caminho da folha 4 até à raiz, com as novas chaves públicas — cada membro existente, dependendo da sua posição, pode já conhecer parte do co-path e deriva o novo Root.secret autonomamente
5. Alice envia ao servidor o novo estado público (apenas os nós que mudaram), o KeyPackage do Eduardo, e a Update Message para os restantes.
6. O servidor incrementa o epoch para 1, atualiza os nós públicos modificados, e distribui as atualizações.
7. Cada membro existente recebe a Update Message, atualiza os nós do co-path que mudaram, e deriva autonomamente o novo Root.secret e a nova GroupKey — **sem precisar de receber um novo KeyPackage cifrado**, porque já têm as chaves privadas do seu próprio caminho.
8. Eduardo recebe o seu KeyPackage, decifra-o, e deriva a GroupKey do epoch 1.

O ponto crítico aqui é o passo 7: os membros existentes **não recebem um blob cifrado novo** para cada um deles individualmente. Apenas recebem as chaves públicas atualizadas dos nós que mudaram. A re-derivação do Root.secret é feita localmente por cada cliente. Isto é o que dá o custo O(log n) em vez de O(n).

### Remoção de um Membro (epoch → epoch + 1)

Suponha que queremos remover Bob (folha 1). O processo é semelhante ao Add, mas mais crítico em termos de segurança: é necessário garantir que Bob não consiga derivar a nova GroupKey mesmo que guarde o Root.secret anterior.

1. O administrador envia ao servidor um pedido de remoção do Bob.
2. O servidor marca a folha 1 como vazia e devolve o estado atual da árvore ao administrador.
3. O cliente administrador executa um **Blank + Update** no caminho da folha 1 até à raiz:
   - Gera novos pares X25519 **completamente novos** para todos os nós no caminho da folha 1 até à raiz
   - Isto é fundamental: como Bob conhecia os segredos destes nós (eram o seu caminho), é necessário substituí-los por segredos completamente novos que Bob não consiga derivar
   - Deriva o novo Root.secret a partir da árvore atualizada
   - Deriva nova GroupKey = HKDF(novo Root.secret, epoch=novo, info="GroupKey")
4. O administrador prepara uma Update Message com as novas chaves **públicas** dos nós atualizados e, para cada membro restante que precise, o caminho cifrado dos nós que mudaram no seu co-path.

O detalhe importante aqui é que alguns membros conseguem derivar o novo Root.secret autonomamente (porque os nós que mudaram estão no seu co-path e eles recebem apenas as novas chaves públicas) e outros precisam de receber um blob cifrado com o segredo de um nó intermédio que mudou no seu caminho direto. Mas em nenhum caso é necessário cifrar o Root.secret diretamente para cada membro — o número de blobs a enviar é O(log n), não O(n).

5. O servidor incrementa o epoch, atualiza o estado público da árvore, e distribui a Update Message.
6. Cada membro restante atualiza o seu estado local e deriva a nova GroupKey.
7. Bob, mesmo que tente usar o Root.secret que guardou, não consegue derivar a nova GroupKey porque ela foi derivada com o novo Root.secret (epoch diferente) e com nós que foram completamente regenerados.

---

## O que Precisa de ser Alterado / Criado

### Base de Dados (`storage.py`)

Precisam de ser adicionadas quatro novas tabelas.

A primeira tabela, `groups`, guarda os metadados de cada grupo: nome único, quem o criou (que é simultaneamente o administrador — este campo define quem tem permissão para fazer Add/Remove), o epoch atual (inteiro), e o número total de folhas na árvore (sempre uma potência de 2). O epoch começa em 0 e incrementa em cada operação Add ou Remove.

A segunda tabela, `group_members`, associa utilizadores a grupos. Cada linha tem o username, o nome do grupo, o índice da folha na árvore (posição fixa do membro), e um campo booleano `active` para marcar remoções sem apagar o histórico. O índice de folha é permanente — quando um membro é removido, a folha fica marcada como vazia mas o índice não é reutilizado imediatamente (simplifica a gestão da árvore).

A terceira tabela, `tree_nodes`, guarda o estado público da árvore: para cada grupo e para cada índice de nó (usando a representação de array de árvore binária completa, onde o nó raiz é o índice 1, os filhos do nó i são 2i e 2i+1), guarda a chave pública X25519 do nó em formato Raw de 32 bytes. Esta tabela é atualizada pelo servidor sempre que o cliente envia uma Update Message após um Add ou Remove. O servidor nunca guarda chaves privadas — apenas as públicas.

A quarta tabela, `group_key_packages`, guarda os KeyPackages cifrados para cada membro em cada epoch. Cada linha tem o nome do grupo, o epoch, o username do membro, e o blob cifrado (que contém os segredos dos nós do caminho desse membro até à raiz, cifrados via Ephemeral-Static ECDH com a chave X25519 pública do membro). Quando um membro se liga e o seu epoch local está desatualizado, recebe o KeyPackage do epoch atual.

A quinta tabela, `group_messages`, guarda mensagens de grupo para membros offline. Tem room_name, sender, epoch (para saber com que GroupKey foi cifrada), e os campos AES-GCM (ciphertext + nonce + tag). É análoga à tabela `offline_messages` mas para grupos.

### Protocol (`protocol/messages.py`)

Precisam de ser adicionados novos tipos de mensagem ao enum `MessageType`:

- `GROUP_CREATE` — cliente envia pedido de criação com lista de membros; servidor responde com chaves públicas de todos os membros
- `GROUP_INIT` — cliente envia o estado inicial da árvore (chaves públicas dos nós) + KeyPackages cifrados para cada membro + epoch = 0
- `GROUP_ADD_MEMBER` — **apenas o administrador** pode enviar este pedido; contém o novo estado dos nós afetados + KeyPackage do novo membro + Update Message para membros existentes; epoch incrementa
- `GROUP_REMOVE_MEMBER` — **apenas o administrador** pode enviar este pedido; contém o novo estado dos nós afetados (completamente regenerados no caminho do membro removido) + Update Messages necessárias; epoch incrementa
- `GROUP_UPDATE` — servidor distribui Update Messages aos membros: contém as novas chaves públicas dos nós que mudaram e, para os membros que precisam, um blob cifrado com o segredo de um nó intermédio do seu caminho
- `GROUP_KEY_PACKAGE` — servidor entrega o KeyPackage cifrado a um membro (no join ou quando o epoch local está desatualizado)
- `GROUP_MSG` — mensagem de grupo cifrada (room_name + epoch + sender + ciphertext + nonce + tag)
- `GROUP_LIST` — listar grupos do utilizador
- `GROUP_INFO` — obter metadados de um grupo (membros ativos, epoch atual, estado público da árvore)

### Servidor (`tcp_handler.py`)

O servidor é deliberadamente simples e **stateless em relação aos segredos** — nunca deriva nenhuma chave, apenas armazena e reencaminha material criptográfico.

Para `GROUP_CREATE`: criar entradas em `groups` e `group_members`, reservar folhas na árvore, devolver ao cliente as chaves públicas X25519 de encriptação de todos os membros.

Para `GROUP_INIT`: receber e guardar o estado público inicial da árvore em `tree_nodes`, guardar os KeyPackages em `group_key_packages`, notificar e entregar KeyPackages aos membros online.

Para `GROUP_ADD_MEMBER` e `GROUP_REMOVE_MEMBER`: o servidor deve primeiro validar que o sender é o administrador do grupo (comparando com o campo `created_by` da tabela `groups`) e rejeitar o pedido caso contrário. Se válido, incrementa o epoch em `groups`, atualiza os nós afetados em `tree_nodes`, guarda os novos KeyPackages em `group_key_packages`, e distribui as Update Messages via `GROUP_UPDATE` a todos os membros online. Para membros offline, guarda as Update Messages pendentes para entregar no próximo login.

Para `GROUP_MSG`: validar membership e epoch, guardar em `group_messages` para offline, reencaminhar a todos os membros online.

### `message_router.py`

Este ficheiro está atualmente vazio. É aqui que deve viver a lógica de broadcast para grupos. O método `broadcast_to_room` recebe a mensagem já cifrada e:

1. Obtém a lista de membros ativos do grupo a partir do storage.
2. Para cada membro online, envia a mensagem diretamente via socket (usando o `OnlineUserManager`).
3. Para cada membro offline, guarda em `group_messages`.

Um novo método `distribute_tree_update` trata da distribuição de Update Messages após Add/Remove: para cada membro, determina quais os nós que mudaram no seu co-path e envia apenas as atualizações relevantes.

### Cliente (`client.py`)

No método `run_cli`, precisam de ser adicionados novos comandos:

- `/group create <nome> <membro1> <membro2> ...` — inicia o processo de criação de grupo
- `/group msg <nome_grupo> <mensagem>` — cifra com a GroupKey do epoch atual e envia
- `/group add <nome_grupo> <novo_membro>` — executa Add + rekeying TreeKEM; **só funciona se o utilizador for o administrador**
- `/group remove <nome_grupo> <membro>` — executa Remove + rekeying TreeKEM; **só funciona se o utilizador for o administrador**
- `/group list` — lista os grupos do utilizador
- `/group info <nome_grupo>` — mostra membros e epoch atual

O cliente também precisa de um handler no `_server_receive_loop` para os novos tipos de mensagem: `GROUP_UPDATE` (atualizar o estado local da árvore e derivar nova GroupKey), `GROUP_KEY_PACKAGE` (decifrar e carregar o KeyPackage), e `GROUP_MSG` (decifrar e apresentar a mensagem).

### `session_manager.py`

Precisam de ser adicionados novos atributos e métodos para gerir o estado TreeKEM local.

Um atributo `group_states` que é um dicionário mapeando `room_name` → estado completo do grupo local. O estado de cada grupo inclui: o epoch atual, a GroupKey derivada, o índice de folha do próprio utilizador, as chaves privadas X25519 dos nós no seu caminho direto até à raiz (array de tamanho log₂(n)), e as chaves públicas dos nós no co-path.

Um método `initialize_tree_as_creator(room_name, members_pub_keys)` que constrói a árvore completa a partir das chaves públicas dos membros, gera os pares X25519 para os nós internos, deriva todos os segredos recursivamente, e prepara os KeyPackages para cada membro.

Um método `derive_root_secret()` que percorre o caminho do próprio utilizador até à raiz, fazendo ECDH com os nós do co-path em cada nível, e retorna o Root.secret.

Um método `derive_group_key(root_secret, epoch)` que aplica HKDF ao Root.secret com o epoch como salt e retorna os 32 bytes da GroupKey.

Um método `process_tree_update(changed_nodes_pub_keys, my_encrypted_path_secret)` que é chamado quando o cliente recebe uma `GROUP_UPDATE`. Atualiza as chaves públicas dos nós que mudaram no co-path. Se recebeu um `my_encrypted_path_secret` (blob cifrado com a sua chave X25519), decifra-o para obter o segredo de um nó intermédio do seu caminho que foi regenerado. Com esta informação, deriva novamente o Root.secret e a nova GroupKey.

Um método `process_key_package(encrypted_blob)` que decifra o KeyPackage recebido do servidor usando a chave X25519 privada estática do utilizador (mesmo mecanismo do `decrypt_offline`), extrai os segredos dos nós do caminho, e reconstrói o estado local da árvore para derivar a GroupKey.

Um método `encrypt_for_group(room_name, plaintext)` que usa a GroupKey do epoch atual para cifrar com AES-GCM.

Um método `decrypt_from_group(room_name, epoch, ciphertext, nonce, tag)` que verifica se o epoch corresponde ao estado atual (ou a um estado anterior guardado em cache) e decifra a mensagem.

Um método `prepare_add_update(room_name, new_member_pub_key)` que calcula quais os nós que precisam de ser atualizados no caminho da nova folha até à raiz, gera novos pares X25519 para esses nós, deriva o novo Root.secret, e prepara o KeyPackage cifrado para o novo membro e as Update Messages para os existentes.

Um método `prepare_remove_update(room_name, removed_member_leaf_index)` que regenera completamente todos os nós no caminho da folha removida até à raiz (novos pares X25519 gerados do zero), deriva o novo Root.secret, e prepara as Update Messages necessárias para os membros restantes.

---

## Representação da Árvore em Memória

A forma mais simples de representar a árvore binária é um array indexado onde o nó raiz está no índice 1, e os filhos do nó i estão nos índices 2i (esquerdo) e 2i+1 (direito). Para uma árvore com 4 folhas, os nós estão nos índices 1 a 7: o nó 1 é a raiz, os nós 2 e 3 são os nós internos do segundo nível, e as folhas estão nos índices 4, 5, 6, 7.

Esta representação facilita a navegação: o pai do nó i é i//2, e o irmão (co-path) é i^1 (XOR com 1). Para calcular o caminho de uma folha até à raiz, basta percorrer i, i//2, i//4, ... até chegar a 1.

O servidor guarda este array de chaves públicas. Cada cliente guarda apenas os índices relevantes para o seu próprio caminho e co-path.

---

## Garantias de Segurança Mantidas

**End-to-End Encryption**: o servidor guarda apenas chaves públicas e blobs cifrados. Nunca tem acesso ao Root.secret nem à GroupKey.

**Forward Secrecy após remoção**: quando um membro é removido, todos os nós no seu caminho são regenerados com material novo. Mesmo que o membro removido tivesse guardado o Root.secret anterior, o novo Root.secret é computacionalmente independente — derivado de chaves X25519 que ele nunca viu.

**Custo O(log n) por Add/Remove**: apenas os nós no caminho da folha afetada até à raiz são atualizados. O número de blobs cifrados enviados ao servidor é proporcional a log₂(n), não a n.

**Autenticidade**: cada Update Message e KeyPackage deve ser assinado com a chave Ed25519 do administrador que iniciou a operação. Os membros verificam esta assinatura contra o certificado do administrador (já emitido pela CA do servidor durante o registo) antes de atualizarem o seu estado local. Isto previne que um servidor comprometido injete atualizações de árvore falsas.

**Sem conhecimento do servidor**: o servidor nunca consegue derivar a GroupKey porque só tem chaves públicas. O ECDH que produz os segredos dos nós internos requer pelo menos uma das chaves privadas dos filhos, que nunca saem dos clientes.

---

## Extras para implementar

**Membros offline durante Add/Remove**: se um membro estiver offline quando o rekeying acontece, precisa de receber um KeyPackage cifrado para o epoch atual quando se ligar. O servidor guarda o KeyPackage mais recente para cada membro em `group_key_packages`, e entrega-o no próximo login. O membro pode ter perdido mensagens de epochs intermédios — estas ficam guardadas em `group_messages` mas só podem ser decifradas se o membro tiver o KeyPackage do epoch correspondente (o servidor deve guardar KeyPackages de todos os epochs enquanto houver mensagens pendentes para aquele membro).

**Histórico para novos membros**: quando um novo membro entra no grupo no epoch k, não consegue ler mensagens de epochs anteriores. Tal como no Sender Keys, isto é uma decisão de design intencional do MLS — novos membros não têm acesso ao histórico.

**Double Ratchet por mensagem**: o TreeKEM gere a rotação de chaves ao nível de grupo (epoch), mas não rotaciona a GroupKey por mensagem. Para maior segurança, pode aplicar-se um ratchet simples sobre a GroupKey (HKDF da GroupKey anterior para derivar a próxima), semelhante ao ratchet C-S já implementado. Isto garante que o comprometimento da GroupKey num momento não expõe mensagens passadas.

## Considerações que não serão implementadas, mas informação útil para o relatório

**Concorrência de operações**: como existe apenas um administrador, não há risco de dois administradores emitirem commits simultâneos. No entanto, o administrador pode tentar fazer dois Add/Remove em rápida sucessão antes de receber a confirmação do servidor do primeiro. O servidor resolve isto simplesmente rejeitando qualquer operação cujo epoch no pedido não corresponda ao epoch atual do grupo — o cliente deve aguardar a confirmação antes de iniciar uma nova operação.

**Transferência de administração**: o sistema descrito tem um único administrador permanente — o criador do grupo. Não existe mecanismo de transferência do papel de administrador. Se o administrador ficar inacessível, ninguém mais consegue fazer Add/Remove. Uma evolução futura seria o administrador poder delegar o papel a outro membro, atualizando o campo `created_by` na tabela `groups` com uma mensagem assinada pela sua chave Ed25519 para garantir autenticidade da transferência.


**Tamanho da árvore**: a implementação descrita usa árvores binárias completas com 2^k folhas. Quando o número de membros não é uma potência de 2, existem folhas vazias. O MLS RFC 9420 usa uma representação mais sofisticada (left-balanced binary trees) que lida com qualquer número de membros de forma mais eficiente. Para uma implementação inicial, árvores de potência de 2 com folhas vazias são suficientes.
