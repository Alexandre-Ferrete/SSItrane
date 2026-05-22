# Projecto de Segurança de Sistemas Informáticos

## Descrição Geral

Desenvolvimento de um sistema de conversação (chat) com **End-to-End Encryption (E2EE)**, garantindo:

- **Confidencialidade** — conteúdo inacessível a terceiros, incluindo o servidor
- **Integridade** — mensagens não podem ser alteradas em trânsito
- **Autenticidade** — identidade dos intervenientes verificável

> Implementação obrigatória em **Python**, utilizando a biblioteca **`cryptography`** para todas as primitivas criptográficas.

---

## Arquitetura do Sistema

### Modelo
Sistema **cliente-servidor**, onde o servidor é um ponto central de coordenação.

### Servidor
- Funciona continuamente, aguardando conexões de clientes
- Responsável pela gestão de utilizadores
- Mantém um diretório de **User -> IP** para permitir comunicação P2P
- **Não encamina mensagens** - apenas fornece IPs aos clientes
- Armazenamento de metadados (ex: listas de contactos)
- Persistência de dados com o mesmo rigor de segurança aplicado às mensagens

### Cliente
- Cada utilizador usa uma instância própria da aplicação
- Após conexão segura ao servidor, funciona como um **interpretador de comandos textuais**
- Permite envio/receção de mensagens e gestão de contactos
- Quando deseja enviar mensagem, pede o IP do destinatário ao servidor e conecta-se diretamente (P2P)
- Comandos específicos ficam ao critério dos alunos

### Identidade
- Cada utilizador possui um **identificador único**
- Suporte a múltiplas sessões simultâneas para o mesmo utilizador fica ao critério dos alunos

### Comunicação P2P
- Recomendada utilização de **sockets TCP**
- Projeto pode ser executado apenas em `localhost`
- Arquitetura deve prever **separação lógica** entre cliente e servidor
- **Fluxo de mensagens:**
  1. Utilizador A faz login → servidor regista IP de A
  2. A quer enviar mensagem a B → pede IP de B ao servidor
  3. Servidor retorna IP de B
  4. A conecta-se diretamente a B (P2P)
  5. A e B comunicam sem passar pelo servidor

---

## Requisitos de Segurança

### Modelo de Confiança
- O servidor é considerado **honesto mas curioso**:
  - Confiável para integridade e aspetos funcionais/gestão de identidades
  - **Não confiável** para confidencialidade dos dados armazenados e trocados

### Ameaças Consideradas
- Ataques de **man-in-the-middle**
- Comprometimento ativo da rede de comunicação

### Garantias Obrigatórias
- **Confidencialidade** de todas as comunicações e informações dos utilizadores
- **Integridade** de todas as comunicações
- **Autenticidade** de toda a comunicação entre utilizadores e servidor

### Gestão de Identidades (base)
- No design mais simples, assume-se que todos os intervenientes pré-partilharam as suas identidades de forma confiável

### Primitivas Criptográficas
Os alunos devem escolher as primitivas mais adequadas, incluindo:
- Protocolos de troca de chaves
- Algoritmos de cifra simétrica e modos de operação

---

## Valorizações (Funcionalidades Avançadas)

| Funcionalidade | Descrição |
|---|---|
| **Mensagens Offline** | Servidor armazena mensagens cifradas quando o destinatário está offline, entregando-as quando ficar online |
| **PKI / Entidade de Certificação** | Servidor actua como CA self-signed, emitindo certificados digitais associados à identidade dos utilizadores (root of trust) |
| **Modo Descentralizado (PGP-like)** | Clientes comunicam diretamente ou de forma assíncrona, sem dependência absoluta do servidor |
| **Mensagens de Grupo** | Chats multi-utilizador com gestão de controlo de acessos e partilha segura de chaves de grupo |
| **Forward Secrecy** | Comprometimento de uma chave não permite decifrar comunicações passadas |

---

## Relatório

O relatório deve ser escrito diretamente em **Markdown** e incluir:

1. **Arquitetura da solução**
   - Fluxos de comunicação
   - Funcionalidades implementadas (incluindo valorizações)
   - Metodologia de gestão de chaves

2. **Modelo de segurança**
   - Explicação fundamentada das primitivas criptográficas utilizadas
   - Análise das garantias de segurança oferecidas
   - Identificação das limitações da solução

3. **Melhorias não implementadas** *(opcional)*
   - Discussão de melhorias funcionais e/ou de segurança que não foram implementadas (ex: falta de tempo, alterações substanciais na arquitetura)

---

## Avaliação

| Componente | Peso |
|---|---|
| Funcionalidade | 25% |
| Segurança | 35% |
| Valorizações | 25% |
| Relatório | 15% |

---

## Entrega e Defesa

- **Data limite:** 24 de Maio de 2026 (até à meia-noite de Portugal Continental)
- **Formato:** Submissão no repositório **GitHub do grupo** (commits até à data limite)
- **Conteúdo a submeter:** todo o código do projeto + relatório

### Defesas
- Sessões de defesa agendadas no fim do semestre com os docentes
- Presença **obrigatória** para obter aprovação
- Nota das componentes práticas é **provisória** até à defesa final
- Nota pode ser ajustada individualmente com base na contribuição e desempenho de cada elemento