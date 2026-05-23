import base64
import os
import socket
import threading
import struct
import json
import time
from typing import Optional, Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from protocol.messages import Message, MessageType
from client.session_manager import SessionManager


def derive_key_PBKDF2HMAC(password: str, salt: Optional[bytes] = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    password_kdf = kdf.derive(password.encode("utf-8"))
    return password_kdf, salt


class ChatClient:
    def __init__(self, server_host: str = 'localhost', server_port: int = 5555, username: str = None):
        self.server_addr   = (server_host, server_port)
        self.server_socket = None
        self.iden_kdf      = None
        self.session_manager = SessionManager(username=username)
        self.username  = None
        self.running   = False

        # Session with Server (Directional Keys for Ratchet)
        self.server_tx_key: Optional[bytes] = None # Client -> Server
        self.server_rx_key: Optional[bytes] = None # Server -> Client

        self.p2p_socket = None
        self.p2p_port   = 0

        self.peer_sessions:   Dict[str, dict] = {}
        self.message_counts:  Dict[str, int]  = {}
        self.pending_chats:   Dict[str, str]  = {}

        # Mensagem pendente enquanto aguarda ratchet
        # { peer: text }
        self.pending_after_ratchet: Dict[str, str] = {}
        
        # Controle de rotação de chave no login
        self.should_rotate_offline_key = False

    # --- Utilitários de Comunicação ---

    def _send_packet(self, sock: socket.socket, message: Message):
        try:
            data_str = message.to_json()
            
            # Se for para o servidor e tivermos chave TX, ciframos e aplicamos Ratchet TX
            if sock == self.server_socket and self.server_tx_key:
                from crypto import symmetric
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                from cryptography.hazmat.primitives import hashes

                # 1. Encriptar com a chave TX atual
                ciphertext, nonce, tag = symmetric.encrypt(self.server_tx_key, data_str.encode('utf-8'))
                
                # 2. Ratchet TX: Gerar próxima chave
                self.server_tx_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"Ratchet"
                ).derive(self.server_tx_key)

                encrypted_payload = {
                    "content": base64.b64encode(ciphertext).decode('utf-8'),
                    "nonce":   base64.b64encode(nonce).decode('utf-8'),
                    "tag":     base64.b64encode(tag).decode('utf-8')
                }
                wrapped = Message(msg_type="encrypted", sender=self.username or "client", payload=encrypted_payload)
                data_str = wrapped.to_json()

            data   = data_str.encode('utf-8')
            header = struct.pack('!I', len(data))
            sock.sendall(header + data)
        except Exception as e:
            print(f"Erro ao enviar: {e}")

    def _recv_packet(self, sock: socket.socket) -> Optional[Message]:
        try:
            header = sock.recv(4)
            if not header:
                return None
            length = struct.unpack('!I', header)[0]

            data_bytes = b""
            while len(data_bytes) < length:
                chunk = sock.recv(min(length - len(data_bytes), 4096))
                if not chunk:
                    break
                data_bytes += chunk

            msg_str = data_bytes.decode('utf-8')
            msg = Message.from_json(msg_str)
            
            # Se for um pacote cifrado do servidor, deciframos e aplicamos Ratchet RX
            if sock == self.server_socket and self.server_rx_key and msg.msg_type == "encrypted":
                from crypto import symmetric
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                from cryptography.hazmat.primitives import hashes

                payload = msg.payload
                ciphertext = base64.b64decode(payload["content"])
                nonce = base64.b64decode(payload["nonce"])
                tag = base64.b64decode(payload["tag"])
                
                # 1. Desencriptar com a chave RX atual
                plaintext = symmetric.decrypt(self.server_rx_key, ciphertext, nonce, tag)
                
                # 2. Ratchet RX: Gerar próxima chave
                self.server_rx_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"Ratchet"
                ).derive(self.server_rx_key)

                return Message.from_json(plaintext.decode('utf-8'))

            return msg
        except Exception as e:
            return None

    # --- Gestão de Conexão com Servidor ---

    def connect(self) -> bool:
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect(self.server_addr)
            
            # --- HANDSHAKE ---
            if not self._perform_server_handshake():
                print("[!] Falha no handshake com o servidor.")
                self.server_socket.close()
                return False

            self.running = True
            threading.Thread(target=self._server_receive_loop, daemon=True).start()
            return True
        except Exception as e:
            print(f"Falha ao ligar ao servidor: {e}")
            return False

    def _perform_server_handshake(self) -> bool:
        """Handshake com o servidor para estabelecer AES-GCM (X25519 + Ed25519)."""
        try:
            # 1. Receber SERVER_HELLO
            msg = self._recv_packet(self.server_socket)
            if not msg or msg.msg_type != MessageType.SERVER_HELLO.value:
                print("[!] Servidor não iniciou handshake corretamente.")
                return False

            server_eph_pub_raw = base64.b64decode(msg.payload.get("pub_key"))
            signature = base64.b64decode(msg.payload.get("signature"))

            # 2. Verificar assinatura do servidor (usando a CA public key local)
            ca_pub_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ca_public.key")
            with open(ca_pub_path, "rb") as f:
                ca_pub_key = serialization.load_pem_public_key(f.read())
            
            ca_pub_key.verify(signature, server_eph_pub_raw)

            # 3. Gerar nossa chave efémera e enviar CLIENT_HELLO
            my_eph_priv = x25519.X25519PrivateKey.generate()
            my_eph_pub_bytes = my_eph_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            client_hello = Message(
                msg_type=MessageType.CLIENT_HELLO.value,
                sender="client",
                payload={"pub_key": base64.b64encode(my_eph_pub_bytes).decode('utf-8')}
            )
            # Enviar diretamente (sem usar _send_packet que poderia tentar cifrar)
            data_raw = client_hello.to_json().encode('utf-8')
            header = struct.pack('!I', len(data_raw))
            self.server_socket.sendall(header + data_raw)

            # 4. Derivar Master Key
            server_eph_pub = x25519.X25519PublicKey.from_public_bytes(server_eph_pub_raw)
            shared_secret = my_eph_priv.exchange(server_eph_pub)

            hkdf_master = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"ServerClientSession"
            )
            master_key = hkdf_master.derive(shared_secret)

            # 5. Derivar Chaves Direcionais para o Ratchet
            # TX (Client -> Server)
            self.server_tx_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"ClientToServer"
            ).derive(master_key)

            # RX (Server -> Client)
            self.server_rx_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"ServerToClient"
            ).derive(master_key)

            print("[*] Canal seguro AES-GCM (TX/RX Ratchet) estabelecido com o servidor.")
            return True

        except Exception as e:
            print(f"[!] Erro no handshake: {e}")
            return False

    def login(self, username, password=None, use_challenge=False, public_key=None):
        if not self.p2p_socket:
            self.start_p2p_listener()

        payload = {"username": username, "p2p_port": self.p2p_port}
        if public_key:
            payload["public_key"] = public_key
        elif use_challenge:
            payload["use_challenge"] = True
        elif password:
            payload["password"] = password

        self._send_packet(self.server_socket, Message(MessageType.AUTH.value, username, payload))

    # --- Lógica P2P ---

    def start_p2p_listener(self):
        self.p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.p2p_socket.bind(('0.0.0.0', 0))
        self.p2p_port = self.p2p_socket.getsockname()[1]
        self.p2p_socket.listen(5)
        threading.Thread(target=self._p2p_accept_loop, daemon=True).start()

    def _p2p_accept_loop(self):
        while self.running:
            client_sock, addr = self.p2p_socket.accept()
            threading.Thread(target=self._handle_peer_connection, args=(client_sock, addr)).start()

    def _handle_peer_connection(self, sock, addr):
        peer_user = None
        try:
            while self.running:
                msg = self._recv_packet(sock)
                if not msg:
                    break

                peer_user = msg.sender

                # ── HANDSHAKE ─────────────────────────────────────────────
                if msg.msg_type == MessageType.P2P_HELLO.value:
                    pub_key_b64   = msg.payload.get("pub_key")
                    signature_b64 = msg.payload.get("signature")
                    cert_b64      = msg.payload.get("cert")

                    # Rejeitar se não tiver assinatura/certificado
                    if not signature_b64 or not cert_b64:
                        print(f"[!!!] Handshake de {peer_user} sem assinatura/certificado. A rejeitar.")
                        sock.close()
                        return

                    # Verificar assinatura Ed25519 sobre chave efémera X25519
                    if not self.session_manager.verify_peer_handshake(
                        peer_user, pub_key_b64, signature_b64, cert_b64
                    ):
                        sock.close()
                        return

                    if peer_user not in self.peer_sessions or self.peer_sessions[peer_user]["socket"] != sock:
                        print(f"[*] A processar handshake inicial de {peer_user}...")
                        handshake_data = self.session_manager.get_handshake_data(peer_user)
                        self.session_manager.process_peer_handshake(peer_user, pub_key_b64)
                        self._send_packet(sock, Message(MessageType.P2P_HELLO.value, self.username, handshake_data))
                        
                        # Fechar socket antigo se existir
                        if peer_user in self.peer_sessions:
                            try: self.peer_sessions[peer_user]["socket"].close()
                            except: pass

                        self.peer_sessions[peer_user] = {"socket": sock}
                    else:
                        # Já estamos neste socket, apenas atualizar derivado (ex: ratchet forçado)
                        self.session_manager.process_peer_handshake(peer_user, pub_key_b64)

                    if peer_user in self.pending_chats:
                        content           = self.pending_chats.pop(peer_user)
                        encrypted_payload = self.session_manager.encrypt_for_peer(peer_user, content)
                        if encrypted_payload:
                            self._send_packet(sock, Message(MessageType.P2P_MSG.value, self.username, encrypted_payload))

                # ── MENSAGEM NORMAL ───────────────────────────────────────
                elif msg.msg_type == MessageType.P2P_MSG.value:
                    texto_limpo = self.session_manager.decrypt_from_peer(peer_user, msg.payload)
                    if texto_limpo:
                        print(f"\n[{peer_user}]: {texto_limpo}")
                    else:
                        print(f"\n[!] Erro de desencriptação com {peer_user}.")

                # ── RATCHET: receber contribuição de salt do peer ─────────
                elif msg.msg_type == MessageType.RATCHET_CONTRIBUTION.value:
                    # Guardar chave antiga para poder enviar resposta (se necessário)
                    old_key = self.session_manager.active_sessions.get(peer_user)
                    if not old_key:
                        continue

                    # 1. Desencriptar o payload com a chave de sessão ATUAL (que ainda é a antiga para o outro lado)
                    plaintext = self.session_manager.decrypt_from_peer(peer_user, msg.payload)
                    if not plaintext:
                        print(f"[!] Falha ao desencriptar contribuição de ratchet de {peer_user}")
                        continue

                    peer_ratchet_data = json.loads(plaintext)
                    peer_salt_b64 = peer_ratchet_data.get("salt_contribution")
                    peer_sig_b64  = peer_ratchet_data.get("signature")

                    # 2. Verificar e derivar nova chave (mas não aplicar ainda em active_sessions)
                    new_key, result = self.session_manager.verify_and_apply_ratchet(
                        peer_user, peer_salt_b64, peer_sig_b64
                    )

                    if new_key and result:
                        # --- RECETOR (BOB) ---
                        # Enviar a nossa contra-contribuição cifrada com a chave ANTIGA
                        # (porque Alice ainda não tem a nova chave)
                        
                        from crypto import symmetric
                        plaintext_bytes = json.dumps(result).encode('utf-8')
                        ciphertext, nonce, tag = symmetric.encrypt(old_key, plaintext_bytes)
                        
                        encrypted_reply = {
                            "content": base64.b64encode(ciphertext).decode('utf-8'),
                            "nonce":   base64.b64encode(nonce).decode('utf-8'),
                            "tag":     base64.b64encode(tag).decode('utf-8')
                        }
                        
                        # Agora Bob pode atualizar para a nova chave
                        self.session_manager.active_sessions[peer_user] = new_key
                        
                        self._send_packet(sock, Message(MessageType.RATCHET_CONTRIBUTION.value, self.username, encrypted_reply))
                        print(f"[*] Contra-contribuição de ratchet enviada e chave atualizada.")

                    elif new_key:
                        # --- INICIADOR (ALICE) ---
                        # Recebemos a resposta do Bob. Agora podemos atualizar a nossa chave.
                        self.session_manager.active_sessions[peer_user] = new_key
                        print(f"[*] Ratchet concluído. Chave atualizada.")

                        # Enviar mensagem pendente (agora com a NOVA chave)
                        pending_text = self.pending_after_ratchet.pop(peer_user, None)
                        if pending_text:
                            encrypted_payload = self.session_manager.encrypt_for_peer(peer_user, pending_text)
                            if encrypted_payload:
                                self._send_packet(sock, Message(MessageType.P2P_MSG.value, self.username, encrypted_payload))
                                print(f"[*] Mensagem pendente enviada com nova chave.")

        except ConnectionResetError:
            print(f"[!] Conexão com {peer_user or 'peer'} foi resetada.")
        except BrokenPipeError:
            print(f"[!] Conexão com {peer_user or 'peer'} foi interrompida.")
        except Exception as e:
            print(f"[!] Erro na conexão com {peer_user or 'peer'}: {e}")
        finally:
            if peer_user and peer_user in self.peer_sessions:
                del self.peer_sessions[peer_user]
                if peer_user in self.session_manager.active_sessions:
                    del self.session_manager.active_sessions[peer_user]
            try:
                sock.close()
            except:
                pass

    def connect_to_peer(self, username, ip, port):
        try:
            if username in self.peer_sessions:
                try:
                    self.peer_sessions[username]["socket"].close()
                except:
                    pass
                del self.peer_sessions[username]
                if username in self.session_manager.active_sessions:
                    del self.session_manager.active_sessions[username]

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, int(port)))

            handshake_data = self.session_manager.get_handshake_data(username)
            self._send_packet(sock, Message(MessageType.P2P_HELLO.value, self.username, handshake_data))

            self.peer_sessions[username] = {"socket": sock}

            threading.Thread(
                target=self._handle_peer_connection,
                args=(sock, (ip, port)),
                daemon=True
            ).start()

        except Exception as e:
            print(f"Erro ao ligar a {username}: {e}")
            if username in self.peer_sessions:
                del self.peer_sessions[username]

    def _initiate_ratchet(self, peer_username: str, pending_text: str):
        """
        Inicia o ratchet P2P:
        1. Gera contribuição de salt local (32 bytes aleatórios) e assina.
        2. Cifra a contribuição com a chave de sessão ATUAL.
        3. Envia ao peer via RATCHET_CONTRIBUTION.
        4. Guarda a mensagem pendente.
        """
        if peer_username not in self.peer_sessions:
            print(f"[!] Sem sessão P2P activa com {peer_username}")
            return

        # Gerar contribuição local
        ratchet_data = self.session_manager.generate_ratchet_contribution(peer_username)

        # Guardar mensagem pendente
        self.pending_after_ratchet[peer_username] = pending_text

        # Cifrar com a chave ATUAL
        encrypted_contribution = self.session_manager.encrypt_for_peer(peer_username, json.dumps(ratchet_data))
        if not encrypted_contribution:
            print(f"[!] Falha ao cifrar contribuição de ratchet")
            return

        self._send_packet(
            self.peer_sessions[peer_username]["socket"],
            Message(MessageType.RATCHET_CONTRIBUTION.value, self.username, encrypted_contribution)
        )
        print(f"[*] Contribuição de ratchet enviada a {peer_username} (cifrada)")

    # --- Loop do Servidor ---

    def _server_receive_loop(self):
        while self.running:
            msg = self._recv_packet(self.server_socket)
            if not msg:
                break

            if msg.msg_type == MessageType.RESPONSE.value:
                status = msg.payload.get("status")
                texto  = msg.payload.get("message")

                if status == "success":
                    print(f"\n[*] SUCESSO: {texto}")

                    # Se o servidor enviou um certificado (CA-signed), guardá-lo
                    cert_b64 = msg.payload.get("certificate")
                    if cert_b64 and self.username:
                        cert_pem = base64.b64decode(cert_b64)
                        cert_path = os.path.join(self.session_manager.data_dir, f"{self.username}_cert.pem")
                        with open(cert_path, "wb") as f:
                            f.write(cert_pem)
                        self.session_manager.identity_cert = cert_pem
                        print(f"[*] Certificado assinado pela CA guardado para {self.username}")

                    if msg.payload.get("require_new_device"):
                        print("[*] Novo dispositivo detetado. A registar...")
                        pub_key = self.session_manager.get_public_key_pem()
                        cert    = self.session_manager.get_certificate()
                        salt    = self.session_manager.get_salt()

                        msg_reg = Message(MessageType.OFFLINE_STORE.value, self.username, {
                            "action":      "register_device",
                            "public_key":  pub_key,
                            "certificate": cert,
                            "salt": base64.b64encode(salt).decode('utf-8') if salt else None
                        })
                        self._send_packet(self.server_socket, msg_reg)
                        continue

                    if "Login OK" in texto:
                        self.device_id = msg.payload.get("device_id")
                        self.username  = msg.payload.get("username")
                        self.session_manager.set_username(self.username)

                        salt_b64 = msg.payload.get("salt")
                        if salt_b64:
                            salt_bytes = base64.b64decode(salt_b64)
                            self.session_manager.set_salt(salt_bytes)
                            
                            if not self.iden_kdf and self.session_manager._temp_password:
                                self.iden_kdf, _ = derive_key_PBKDF2HMAC(self.session_manager._temp_password, salt_bytes)

                        # Carregar chaves locais (incluindo X25519 antiga para ler mensagens pendentes)
                        self.session_manager.load_identity_keys(self.iden_kdf, self.username)

                        # Agendar rotação para DEPOIS de recebermos as mensagens offline
                        self.should_rotate_offline_key = True

                        nonce             = msg.payload.get("nonce")
                        require_challenge = msg.payload.get("require_challenge")

                        priv_path = os.path.join(self.session_manager.data_dir, f"{self.username}_priv.pem")
                        if os.path.exists(priv_path) and os.path.getsize(priv_path) > 0 and require_challenge:
                            nonce_enc = self.session_manager.sign_with_identity_key(nonce.encode('utf-8'))
                            req = Message(MessageType.OFFLINE_STORE.value, self.username, {
                                "action":          "get",
                                "nonce_encrypted": base64.b64encode(nonce_enc).decode('utf-8')
                            })
                        else:
                            req = Message(MessageType.OFFLINE_STORE.value, self.username, {"action": "get"})

                        self._send_packet(self.server_socket, req)

                elif status == "error":
                    print(f"\n[*] ERRO: {texto}")

            elif msg.msg_type == MessageType.IP_RESPONSE.value:
                dest_user = msg.payload.get('target_user')
                ip        = msg.payload.get('ip')
                port      = msg.payload.get('port')

                if ip:
                    print(f"[*] {dest_user} encontrado em {ip}:{port}. A conectar...")
                    self.connect_to_peer(dest_user, ip, port)
                else:
                    print(f"[!] {dest_user} está offline. A guardar mensagem segura...")
                    if dest_user in self.pending_chats:
                        content     = self.pending_chats.pop(dest_user)
                        enc_key_b64 = msg.payload.get("encryption_key")
                        
                        if enc_key_b64:
                            # Ephemeral-Static ECDH
                            encrypted_data = self.session_manager.encrypt_offline(enc_key_b64, content)
                            if encrypted_data:
                                msg_off = Message(MessageType.OFFLINE_STORE.value, self.username, {
                                    "action":        "store",
                                    "recipient":     dest_user,
                                    "content":       encrypted_data["content"],
                                    "nonce":         encrypted_data.get("nonce"),
                                    "tag":           encrypted_data.get("tag"),
                                    "ephemeral_key": encrypted_data.get("ephemeral_key")
                                })
                                self._send_packet(self.server_socket, msg_off)
                        else:
                            print(f"[!] {dest_user} não tem chave de encriptação registada.")

            elif msg.msg_type == MessageType.USERS_LIST.value:
                print(f"[*] Utilizadores Online: {msg.payload.get('users')}")

            elif msg.msg_type == "offline_messages":
                mensagens = msg.payload.get("messages", [])
                if not mensagens:
                    print("\n[*] Não tens mensagens offline pendentes.")
                
                for m in mensagens:
                    sender = m.get("sender")
                    try:
                        print(f"[*] A processar mensagem offline de {sender}...")
                        texto_limpo = self.session_manager.decrypt_offline(m)
                        print(f"\n[OFFLINE][{sender}]: {texto_limpo}")
                    except Exception as e:
                        print(f"\n[OFFLINE][{sender}]: (Erro ao desencriptar: {e})")

                # --- AGORA ROTACIONAR ---
                # Só rotacionamos depois de tentarmos desencriptar as mensagens pendentes
                if self.should_rotate_offline_key and self.iden_kdf:
                    new_enc_key_raw = self.session_manager.rotate_encryption_key(self.iden_kdf)
                    update_msg = Message(MessageType.UPDATE_KEYS.value, self.username, {
                        "encryption_key": base64.b64encode(new_enc_key_raw).decode('utf-8')
                    })
                    self._send_packet(self.server_socket, update_msg)
                    self.should_rotate_offline_key = False
                    print("[*] Chave de encriptação offline rotacionada com sucesso.")

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("Desconectado.")

    def run_cli(self):
        print("\n=== BEM-VINDO AO SECURE P2P CHAT ===")
        print("Comandos disponíveis:")
        print("  /register <user> <pass>  - Criar nova conta")
        print("  /login <user> <pass>     - Entrar na conta")
        print("  /chat <user> <msg>       - Enviar mensagem (P2P)")
        print("  /list                    - Ver quem está online")
        print("  /exit                    - Sair do programa")
        print("===================================\n")

        while self.running:
            raw_input = input(f"[{self.username or 'Anonimo'}] > ").strip()
            if not raw_input:
                continue

            parts = raw_input.split(" ", 2)
            cmd   = parts[0].lower()

            if cmd == "/register" and len(parts) == 3:
                user, pwd = parts[1], parts[2]
                pwd_kdf, salt = derive_key_PBKDF2HMAC(pwd, None)
                self.iden_kdf = pwd_kdf
                
                # Gera identidade Ed25519 e encriptação estática X25519
                pub_key_b64   = self.session_manager.load_or_generate_identity_keys(pwd_kdf, user)
                cert_b64      = self.session_manager.get_certificate()
                enc_key_raw   = self.session_manager.get_encryption_key_raw()

                salt_path = os.path.join(self.session_manager.data_dir, f"{user}.salt")
                with open(salt_path, "wb") as f:
                    f.write(salt)

                msg = Message(MessageType.REGISTER.value, user, {
                    "username":       user,
                    "password":       base64.b64encode(pwd_kdf).decode('utf-8'),
                    "public_key":     pub_key_b64,
                    "certificate":    cert_b64,
                    "encryption_key": base64.b64encode(enc_key_raw).decode('utf-8') if enc_key_raw else None,
                    "salt":           base64.b64encode(salt).decode('utf-8'),
                })
                self._send_packet(self.server_socket, msg)
                print("[*] Pedido de registo enviado ao servidor!")

            elif cmd == "/login" and len(parts) == 3:
                if self.username:
                    print("[!] Já tens sessão iniciada!")
                else:
                    user, pwd = parts[1], parts[2]
                    priv_path = os.path.join(self.session_manager.data_dir, f"{user}_priv.pem")
                    pub_path  = os.path.join(self.session_manager.data_dir, f"{user}_pub.pem")
                    has_keys  = os.path.exists(priv_path) and os.path.exists(pub_path)

                    self.session_manager.set_password(pwd)

                    if has_keys:
                        with open(pub_path, "rb") as f:
                            pub_key_pem = f.read().decode('utf-8')
                        self.login(user, public_key=base64.b64encode(pub_key_pem.encode()).decode('utf-8'))
                    else:
                        self.login(user, password=pwd)

            elif cmd == "/chat" and len(parts) > 2:
                if not self.username:
                    print("[!] Precisas de fazer /login primeiro.")
                    continue

                target, text = parts[1], parts[2]

                if target in self.peer_sessions:
                    current_count = self.message_counts.get(target, 0) + 1
                    self.message_counts[target] = current_count

                    # A cada 10 mensagens, iniciar ratchet P2P
                    if current_count % 5 == 0:
                        self._initiate_ratchet(target, text)
                        continue

                    payload = self.session_manager.encrypt_for_peer(target, text)
                    if payload:
                        try:
                            self._send_packet(
                                self.peer_sessions[target]["socket"],
                                Message(MessageType.P2P_MSG.value, self.username, payload)
                            )
                        except (BrokenPipeError, ConnectionResetError, OSError) as e:
                            print(f"[!] Erro ao enviar para {target}: {e}")
                            del self.peer_sessions[target]
                            if target in self.session_manager.active_sessions:
                                del self.session_manager.active_sessions[target]
                            self.message_counts[target] = 0
                            self.pending_chats[target]  = text
                            self._send_packet(self.server_socket,
                                Message(MessageType.GET_IP.value, self.username, {"target_user": target}))
                else:
                    self.pending_chats[target] = text
                    self._send_packet(self.server_socket,
                        Message(MessageType.GET_IP.value, self.username, {"target_user": target}))

            elif cmd == "/list":
                if not self.username:
                    print("[!] Precisas de fazer /login primeiro.")
                else:
                    self._send_packet(self.server_socket,
                        Message(MessageType.GET_USERS.value, self.username, {}))

            elif cmd == "/exit":
                if self.username:
                    self._send_packet(self.server_socket,
                        Message(MessageType.DISCONNECT.value, self.username, {}))
                self.stop()

            else:
                print("[!] Comando inválido ou formato incorreto.")


if __name__ == "__main__":
    server_host = input("Endereço IP do servidor [localhost]: ").strip() or "localhost"
    client = ChatClient(server_host=server_host, server_port=5555)
    if client.connect():
        client.run_cli()