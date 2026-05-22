# Especificação Técnica: Sistema de Chat P2P com E2EE e PKI

Este documento detalha a arquitetura de segurança para um sistema de chat Peer-to-Peer (P2P) resiliente, garantindo Confidencialidade, Integridade e Autenticidade [cite: Requirements.md].

---

## 1. Arquitetura de Identidade (PKI & CA)

O servidor funciona como uma **Autoridade Certificadora (CA)**, atuando como a "Root of Trust" do sistema [cite: Requirements.md].

* **Geração da CA (Servidor):** O servidor gera um par de chaves RSA (4096-bit) e um certificado auto-assinado (Root CA).
* **Registo e Certificação:**
    * Cada cliente gera localmente um par de chaves **Ed25519** (para assinaturas digitais) [cite: Requirements.md].
    * O cliente envia um **CSR (Certificate Signing Request)** ao servidor.
    * O servidor assina a chave pública do cliente, emitindo um certificado **X.509**.
* **Login e Autenticação:** Baseado num desafio de assinatura digital para provar a posse da chave privada associada ao certificado.

---

## 2. Comunicação Peer-to-Peer e PFS

A comunicação entre utilizadores é feita diretamente via **TCP Sockets**, sem que o servidor encaminhe mensagens [cite: Requirements.md].

### Perfect Forward Secrecy (PFS)
Para garantir que o comprometimento de uma chave de longo prazo não comprometa sessões passadas, implementamos **ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)**:

1.  **Troca Efêmera:** Para cada nova conversa, os clientes geram chaves temporárias (X25519).
2.  **Assinatura de Handshake:** As chaves públicas efêmeras são assinadas com as chaves Ed25519 certificadas pela CA. Isto impede ataques **Man-In-The-Middle (MITM)** durante a negociação de chaves.
3.  **Derivação de Chave:** O segredo partilhado é processado por uma **HKDF (Key Derivation Function)** para gerar a chave de sessão final.

---

## 3. Criptografia de Dados em Trânsito

* **Primitiva:** **AES-256-GCM**.
* **Segurança:** Este é um modo de cifragem autenticada (AEAD). Ele fornece:
    * **Confidencialidade:** Os dados são cifrados.
    * **Integridade:** Qualquer alteração nos dados em trânsito invalida a "Tag" de autenticação, lançando uma exceção no cliente recetor [cite: Requirements.md].

---

## 4. Mensagens de Grupo

Implementação de **Sender Keys** para eficiência:
* **Criação:** O administrador gera uma **Group Symmetric Key (GSK)**.
* **Distribuição:** A GSK é enviada a cada membro através de túneis P2P cifrados individualmente com PFS.
* **Sair do Grupo:** Quando um membro sai, o administrador gera e distribui uma nova GSK para manter a segurança para o futuro (Forward Secrecy de grupo).

---

## 5. Resiliência e Modo Offline

O sistema prevê a queda do servidor através de **Caching de Identidade**:
* **Armazenamento Local:** O cliente mantém uma base de dados local (cifrada com `Fernet` baseada na password do utilizador) contendo IPs e certificados públicos de contactos conhecidos.
* **Operação Fallback:** Se o servidor estiver offline, o cliente tenta a ligação P2P direta usando o IP em cache. A autenticidade é validada localmente verificando se o certificado do parceiro ainda é válido e assinado pela CA Root que o cliente já conhece.

---

## 6. Primitivas Criptográficas (Biblioteca `cryptography`)

| Função | Algoritmo | Implementação em Python |
| :--- | :--- | :--- |
| **Identidade** | Ed25519 | `hazmat.primitives.asymmetric.ed25519` |
| **Cifra P2P** | AES-256-GCM | `hazmat.primitives.ciphers.aead.AESGCM` |
| **PFS (Troca)** | X25519 | `hazmat.primitives.asymmetric.x25519` |
| **Hashing** | SHA-256 | `hazmat.primitives.hashes.SHA256` |
| **Derivação** | HKDF | `hazmat.primitives.kdf.hkdf.HKDF` |
| **Certificados** | X.509 | `cryptography.x509` |

---

## 7. Fluxo de Ataque e Defesa (MITM)

Em caso de ataque MITM:
1.  O atacante tenta intercetar o handshake ECDHE.
2.  O atacante teria de apresentar a sua própria chave pública efêmera.
3.  No entanto, o atacante **não possui** um certificado assinado pela CA do servidor para a identidade da vítima.
4.  O cliente A deteta que a assinatura da chave pública efêmera recebida não é válida ou o certificado não é confiável, terminando a conexão imediatamente.

---
