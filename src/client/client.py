import base64
import os
import socket
import threading
import struct
import json
import time
from crypto.signatures import generate_keypair_Ed25519
from crypto.kdf import derive_key_PBKDF2HMAC
from typing import Optional, Dict
from protocol.messages import Message, MessageType
from client.session_manager import SessionManager
from crypto.ecdh import generate_keypair


class ChatClient:
    def __init__(self, server_host: str = 'localhost', server_port: int = 5555, username: str = None):
        self.server_addr   = (server_host, server_port)
        self.server_socket = None
        self.iden_kdf      = None
        self.session_manager = SessionManager(username=username)
        self.username  = None
        self.running   = False

        self.p2p_socket = None
        self.p2p_port   = 0

        self.peer_sessions:   Dict[str, dict] = {}
        self.message_counts:  Dict[str, int]  = {}
        self.pending_chats:   Dict[str, str]  = {}

        # Mensagem pendente enquanto aguarda ratchet
        # { peer: text }
        self.pending_after_ratchet: Dict[str, str] = {}

    # --- Utilitários de Comunicação ---

    def _send_packet(self, sock: socket.socket, message: Message):
        try:
            data   = message.to_json().encode('utf-8')
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

            data = b""
            while len(data) < length:
                chunk = sock.recv(min(length - len(data), 4096))
                if not chunk:
                    break
                data += chunk

            return Message.from_json(data.decode('utf-8'))
        except:
            return None

    # --- Gestão de Conexão com Servidor ---

    def connect(self) -> bool:
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect(self.server_addr)
            self.running = True
            threading.Thread(target=self._server_receive_loop, daemon=True).start()
            return True
        except Exception as e:
            print(f"Falha ao ligar ao servidor: {e}")
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

                    if peer_user not in self.peer_sessions:
                        print(f"[*] A processar handshake inicial de {peer_user}...")
                        handshake_data = self.session_manager.get_handshake_data(peer_user)
                        self.session_manager.process_peer_handshake(peer_user, pub_key_b64)
                        self._send_packet(sock, Message(MessageType.P2P_HELLO.value, self.username, handshake_data))
                        self.peer_sessions[peer_user] = {"socket": sock}
                    else:
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
                    # O payload chega cifrado como mensagem normal P2P,
                    # por isso desencriptamos primeiro
                    peer_contribution_b64_enc = msg.payload

                    # Desencriptar a contribuição (foi enviada cifrada)
                    raw = self.session_manager.decrypt_from_peer(peer_user, peer_contribution_b64_enc)
                    if not raw:
                        print(f"[!] Falha ao desencriptar contribuição de ratchet de {peer_user}")
                        continue

                    # raw é a contribuição do peer em base64 (dentro do plaintext)
                    peer_contribution_b64 = raw

                    # Aplicar ratchet combinando as duas contribuições
                    ok = self.session_manager.apply_ratchet_with_peer_contribution(
                        peer_user, peer_contribution_b64
                    )

                    if ok:
                        # Se tínhamos uma mensagem pendente para enviar após o ratchet, enviá-la agora
                        pending_text = self.pending_after_ratchet.pop(peer_user, None)
                        if pending_text:
                            encrypted_payload = self.session_manager.encrypt_for_peer(peer_user, pending_text)
                            if encrypted_payload:
                                try:
                                    self._send_packet(
                                        self.peer_sessions[peer_user]["socket"],
                                        Message(MessageType.P2P_MSG.value, self.username, encrypted_payload)
                                    )
                                    print(f"[*] Mensagem enviada após ratchet: {pending_text}")
                                except Exception as e:
                                    print(f"[!] Erro ao enviar após ratchet: {e}")

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
        1. Gera contribuição de salt local (32 bytes aleatórios)
        2. Cifra a contribuição com a chave de sessão atual
        3. Envia ao peer via RATCHET_CONTRIBUTION
        4. Guarda a mensagem pendente — será enviada quando o peer responder
           com a sua contribuição e o ratchet for aplicado

        O servidor não é envolvido — o salt final é SHA-256(contrib_A || contrib_B)
        e nunca sai do canal P2P cifrado.
        """
        if peer_username not in self.peer_sessions:
            print(f"[!] Sem sessão P2P activa com {peer_username}")
            return

        # Gerar contribuição local e guardá-la no session_manager
        my_contribution_b64 = self.session_manager.generate_salt_contribution(peer_username)

        # Guardar mensagem pendente para enviar após o ratchet
        self.pending_after_ratchet[peer_username] = pending_text

        # Cifrar a contribuição com a chave de sessão ATUAL antes de enviar
        encrypted_contribution = self.session_manager.encrypt_for_peer(peer_username, my_contribution_b64)
        if not encrypted_contribution:
            print(f"[!] Falha ao cifrar contribuição de ratchet")
            return

        self._send_packet(
            self.peer_sessions[peer_username]["socket"],
            Message(MessageType.RATCHET_CONTRIBUTION.value, self.username, encrypted_contribution)
        )
        print(f"[*] Contribuição de ratchet enviada a {peer_username} (servidor não envolvido)")

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

                        salt = msg.payload.get("salt")
                        if salt:
                            self.session_manager.set_salt(base64.b64decode(salt))

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
                    print(f"[!] {dest_user} está offline. A guardar mensagem...")
                    if dest_user in self.pending_chats:
                        content        = self.pending_chats.pop(dest_user)
                        pub_key        = msg.payload.get("public_key")
                        encrypted_data = self.session_manager.encrypt_offline(pub_key, content)
                        msg_off = Message(MessageType.OFFLINE_STORE.value, self.username, {
                            "action":    "store",
                            "recipient": dest_user,
                            "content":   encrypted_data["content"],
                            "nonce":     encrypted_data.get("nonce"),
                            "tag":       encrypted_data.get("tag")
                        })
                        self._send_packet(self.server_socket, msg_off)

            elif msg.msg_type == MessageType.USERS_LIST.value:
                print(f"[*] Utilizadores Online: {msg.payload.get('users')}")

            elif msg.msg_type == "offline_messages":
                mensagens = msg.payload.get("messages", [])
                if not mensagens:
                    print("\n[*] Não tens mensagens offline pendentes.")
                for m in mensagens:
                    sender = m.get("sender")
                    try:
                        texto_limpo = self.session_manager.decrypt_offline(m)
                        print(f"\n[OFFLINE][{sender}]: {texto_limpo}")
                    except Exception as e:
                        print(f"\n[OFFLINE][{sender}]: (Erro ao desencriptar: {e})")

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
                pub_key_b64   = self.session_manager.load_or_generate_identity_keys(pwd_kdf, user)
                cert_b64      = self.session_manager.get_certificate()

                salt_path = os.path.join(self.session_manager.data_dir, f"{user}.salt")
                with open(salt_path, "wb") as f:
                    f.write(salt)

                msg = Message(MessageType.REGISTER.value, user, {
                    "username":    user,
                    "password":    base64.b64encode(pwd_kdf).decode('utf-8'),
                    "public_key":  pub_key_b64,
                    "certificate": cert_b64,
                    "salt":        base64.b64encode(salt).decode('utf-8'),
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
                    if current_count % 10 == 0:
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