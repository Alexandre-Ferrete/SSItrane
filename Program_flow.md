# Program Flow

## 1. Overview

This project implements a secure end-to-end encrypted chat system with a hybrid client-server and P2P architecture. The server is responsible for user registration, authentication, and directory services, while clients handle direct encrypted messaging between peers.

Key modules:
- `src/server/server.py` - server entrypoint and main coordination logic
- `src/client/client.py` - client networking, server connection, and P2P connection management
- `src/client/cli.py` - command interpreter and user interface
- `src/protocol/messages.py` - protocol message types and payload definitions
- `src/crypto/ecdh.py` - ECDH key exchange and key derivation
- `src/crypto/symmetric.py` - AES-GCM encryption primitives

## 1.1 Encryption strategy

All messaging uses authenticated symmetric encryption with AES-GCM. Session keys are derived from ECDH exchanges and HKDF-SHA256, providing confidentiality and integrity. Long-term keys and public-key certificates are used for identity authentication and key agreement, while RSA/ECC hybrid encryption can be used for key encapsulation.

## 2. Startup Flow

### 2.1 Server startup

1. Execute `python3 -m server.server --host 0.0.0.0 --port 6767` from `src/`.
2. `ChatServer.__init__()` initializes server configuration, placeholders for storage, user manager, and message router.
3. `ChatServer.start()` creates a listening TCP socket, binds to the host and fixed port `6767`, and begins accepting client connections.
4. For each incoming connection, the server creates a client handler thread and continues accepting new clients.

### 2.2 Client startup

1. Execute `python3 -m client.client --host localhost --port 6767` from `src/`.
2. `ChatClient.__init__()` initializes server address, socket state, P2P listener state, and connection maps.
3. `ChatClient.connect()` opens a TCP connection to the server at the fixed port `6767`, establishes an encrypted client-server channel, and starts the server receive loop in a new thread.
4. `ChatClient.start_p2p_listener()` opens a second TCP socket on the local fixed port `6767` and starts a P2P accept loop thread.
5. The client enters the command loop via `ChatClient.run()` and waits for user commands.

## 3. User Registration and Authentication Flow

### 3.1 Registration

1. The user enters the `register <username> <password>` command in the CLI.
2. The client validates the input locally and constructs a `register` request message.
3. The client sends the request over the encrypted client-server channel using length-prefixed JSON.
4. The server receives the `register` request and performs validation:
   - checks if the username exists
   - validates password and username format
   - stores the new user name, hash password and IP
5. The server returns a `register_response` to the client indicating success or failure.
6. The client displays the result to the user.

### 3.2 Authentication (login)

1. The user enters the `login <username> <password>` command.
2. The client sends an `auth` request to the server over the encrypted channel.
3. The server verifies credentials against stored user data.
4. On success, the server records the client as online and stores the username → IP mapping in `user_manager`.
5. The server sends an `auth_response` back to the client.
6. The client receives the response, records the authenticated username, and continues command processing.
7. The client keeps a secure TCP connection with the server and remains ready to receive server notifications.

## 4. Server Directory and Online Presence Flow

1. After successful login, the server associates the client username with the IP address of the TCP connection.
2. The server maintains an online directory of active users and their reachable IP address or socket details.
3. Clients can query the server with `get_users` to receive the current list of online users via the encrypted channel.
4. When a client requests the IP of another user via `get_ip`, the server replies with an `ip_response` containing the target peer address if online.
5. When a client disconnects or logs out, the server removes that user from the online directory and notifies other users if implemented.

## 5. Peer-to-Peer Connection Flow

### 5.1 Connection establishment

1. A logged-in client decides to message another user and issues `connect <username>` or `msg <username> <message>`.
2. The client sends a `get_ip` request to the server for the recipient username over the encrypted channel.
3. The server replies with `ip_response`, including the recipient's IP address and the fixed P2P port `6767`.
4. The client parses the address and calls `connect_to_peer(ip, port=6767)`.
5. `connect_to_peer()` creates a direct TCP socket to the peer's P2P listener on port `6767`.
6. The client stores the active P2P socket in `p2p_connections` for later messaging.

### 5.2 Receiving peer connections

1. Each client maintains a P2P listener socket opened by `start_p2p_listener()` on port `6767`.
2. Incoming peer connections are accepted in `_p2p_accept_loop()`.
3. Each accepted peer socket is handled by `_handle_p2p_client()` in a separate thread.
4. Incoming P2P messages are parsed and passed to the configured message callback for display.

## 6. Encrypted Chat Messaging Flow

### 6.1 Message format and transport

1. All messages are sent over TCP using a length-prefixed protocol:
   - 4-byte big-endian length
   - JSON payload of the declared size
2. Client-server messages use types defined in `src/protocol/messages.py`.
3. All message payloads are encrypted with AES-GCM, which provides both confidentiality and integrity.
4. P2P chat messages are also serialized as JSON and sent over the active peer connection.

### 6.2 Cryptographic message exchange

1. Before sending encrypted chat content, the client performs an ECDH key exchange flow using `src/crypto/ecdh.py`.
2. The sender generates an ephemeral keypair and includes the ephemeral public key with the encrypted message.
3. The recipient uses its private key and the sender's ephemeral public key to derive a shared secret.
4. `derive_key()` applies HKDF-SHA256 to the raw shared secret and produces a symmetric AES key.
5. The message payload is encrypted with AES-GCM from `src/crypto/symmetric.py`.
6. The encrypted payload includes ciphertext, nonce, and authentication tag.
7. The sender sends the encrypted chat message to the peer over the P2P socket.
8. The receiver decrypts and authenticates the message, then presents plaintext if verification succeeds.

## 7. Client Command Flow

### 7.1 Core commands

- `register <username> <password>`: register a new account
- `login <username> <password>`: authenticate to the server
- `msg <username> <message>`: send a P2P encrypted message
- `connect <username>`: request peer IP and establish P2P connection
- `users`: request online users list
- `rooms`: request available chat rooms
- `create_room <name>`: create a new room
- `join <room_name>`: join a room
- `leave <room_name>`: leave a room
- `logout`: disconnect from the server
- `exit`: close the client

### 7.2 Command handling

1. The CLI parses user input into actions and arguments.
2. Each command triggers one or more client methods.
3. Commands that require server state send the appropriate JSON request to the server over the encrypted channel.
4. Responses from the server are handled asynchronously by `_receive_loop()` and `_handle_server_message()`.
5. P2P messaging commands send direct peer messages once the peer connection is established.

## 8. Room and Offline Messaging Flow (Design)

Although the code contains placeholders for room support, the intended flow is:

1. `create_room` sends a `create_room` request to the server.
2. `join_room` and `leave_room` send corresponding room management requests.
3. `room_message` is broadcast by the server to room participants.
4. Offline messages are requested with `get_offline`, and the server returns queued encrypted messages via `offline_messages`.
5. Whenever a user tries to send a message to another offline user, they receive an error from the server stating that the user is offline. The sender may then store the encrypted message for later delivery.

## 9. Shutdown Flow

### 9.1 Client shutdown

1. The user issues `logout` or `exit`.
2. The client sends a `disconnect` request to the server.
3. The client closes the server socket, P2P listener socket, and any active P2P connections.
4. The client stops its receive and accept threads.

### 9.2 Server shutdown

1. The server receives a termination signal or admin stop command.
2. `ChatServer.shutdown()` sets the running flag to false.
3. The server closes the listening socket and waits for client threads to finish.
4. Active client connections are closed gracefully.

## 10. Data Flow Summary

1. Client CLI → `ChatClient` → encrypted TCP channel to server
2. Server → authentication/user management → directory updates
3. Client → server `get_ip` → server returns peer address and fixed P2P port `6767`
4. Client → direct peer connection on fixed port `6767` → encrypted P2P JSON messages
5. Peer → decrypt and display message via CLI callback

## 11. Security Flow Summary

- Client-server communication is encrypted to protect authentication and directory traffic.
- The server is a directory service, not a message relay.
- Client-to-client traffic is encrypted end-to-end.
- ECDH provides shared secret derivation and supports perfect forward secrecy.
- AES-GCM provides confidentiality and integrity of message payloads.
- Message types and payloads are defined consistently in `src/protocol/messages.py`.

---

This document captures the program flow for the current implementation and the intended secure communication lifecycle supported by the system.