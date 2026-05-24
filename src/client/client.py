import base64
import os
import socket
import threading
import struct
import json
import time
import traceback
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from protocol.messages import Message, MessageType
from client.session_manager import SessionManager, derive_key_PBKDF2HMAC
from crypto import symmetric


class ChatClient:
    def __init__(self, server_host: str = 'localhost', server_port: int = 5555, username: str = None):
        self.server_addr   = (server_host, server_port)
        self.server_socket = None
        self.iden_kdf      = None
        self.session_manager = SessionManager(username=username)
        self.username  = username
        self.running   = False

        # Session with Server
        self.server_tx_key: Optional[bytes] = None
        self.server_rx_key: Optional[bytes] = None
        
        # Concurrency
        self.socket_locks: Dict[socket.socket, threading.Lock] = {}
        self.global_lock = threading.Lock()

        self.p2p_socket = None
        self.p2p_port   = 0

        self.peer_sessions:   Dict[str, dict] = {}
        self.message_counts:  Dict[str, int]  = {}
        self.pending_chats:   Dict[str, str]  = {}
        
        self.should_rotate_offline_key = False
        self.pending_group_actions: Dict[str, dict] = {}

    def _get_sock_lock(self, sock: socket.socket) -> threading.Lock:
        with self.global_lock:
            if sock not in self.socket_locks:
                self.socket_locks[sock] = threading.Lock()
            return self.socket_locks[sock]

    def _send_packet(self, sock: socket.socket, message: Message):
        try:
            lock = self._get_sock_lock(sock)
            with lock:
                data_str = message.to_json()
                if sock == self.server_socket and self.server_tx_key:
                    ciphertext, nonce, tag = symmetric.encrypt(self.server_tx_key, data_str.encode('utf-8'))
                    self.server_tx_key = HKDF(hashes.SHA256(), 32, None, b"Ratchet").derive(self.server_tx_key)
                    wrapped = Message(msg_type="encrypted", sender=self.username or "client", payload={
                        "content": base64.b64encode(ciphertext).decode('utf-8'),
                        "nonce":   base64.b64encode(nonce).decode('utf-8'),
                        "tag":     base64.b64encode(tag).decode('utf-8')
                    })
                    data_str = wrapped.to_json()

                data = data_str.encode('utf-8')
                header = struct.pack('!I', len(data))
                sock.sendall(header + data)
        except Exception as e:
            if self.running: print(f"[!] Erro ao enviar pacote: {e}")

    def _recv_packet(self, sock: socket.socket) -> Optional[Message]:
        try:
            header = sock.recv(4)
            if not header or len(header) < 4: return None
            length = struct.unpack('!I', header)[0]
            data_bytes = b""
            while len(data_bytes) < length:
                chunk = sock.recv(min(length - len(data_bytes), 4096))
                if not chunk: break
                data_bytes += chunk
            if len(data_bytes) < length: return None
            msg_str = data_bytes.decode('utf-8')
            msg = Message.from_json(msg_str)
            if not msg: return None
            if sock == self.server_socket and self.server_rx_key and msg.msg_type == "encrypted":
                plaintext = symmetric.decrypt(self.server_rx_key, base64.b64decode(msg.payload["content"]), base64.b64decode(msg.payload["nonce"]), base64.b64decode(msg.payload["tag"]))
                self.server_rx_key = HKDF(hashes.SHA256(), 32, None, b"Ratchet").derive(self.server_rx_key)
                return Message.from_json(plaintext.decode('utf-8'))
            return msg
        except: return None

    def connect(self) -> bool:
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.settimeout(10); self.server_socket.connect(self.server_addr)
            if not self._perform_server_handshake(): return False
            self.running = True
            threading.Thread(target=self._server_receive_loop, daemon=True).start()
            return True
        except Exception as e: print(f"[!] Erro ao ligar ao servidor: {e}"); return False

    def _perform_server_handshake(self) -> bool:
        try:
            msg = self._recv_packet(self.server_socket)
            if not msg or msg.msg_type != MessageType.SERVER_HELLO.value: return False
            spub_raw, sig = base64.b64decode(msg.payload.get("pub_key")), base64.b64decode(msg.payload.get("signature"))
            ca_pub_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ca_public.key")
            with open(ca_pub_path, "rb") as f: serialization.load_pem_public_key(f.read()).verify(sig, spub_raw)
            my_eph_priv = x25519.X25519PrivateKey.generate()
            my_eph_pub  = my_eph_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            client_hello = Message(MessageType.CLIENT_HELLO.value, "client", {"pub_key": base64.b64encode(my_eph_pub).decode('utf-8')})
            h_json = client_hello.to_json().encode('utf-8')
            self.server_socket.sendall(struct.pack('!I', len(h_json)) + h_json)
            master = HKDF(hashes.SHA256(), 32, None, b"ServerClientSession").derive(my_eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(spub_raw)))
            self.server_tx_key = HKDF(hashes.SHA256(), 32, None, b"ClientToServer").derive(master)
            self.server_rx_key = HKDF(hashes.SHA256(), 32, None, b"ServerToClient").derive(master)
            print("[*] Canal seguro com o servidor estabelecido.")
            return True
        except: return False

    def login(self, username, password=None, public_key=None):
        if not self.p2p_socket: self.start_p2p_listener()
        self._send_packet(self.server_socket, Message(MessageType.AUTH.value, username, {"username": username, "p2p_port": self.p2p_port, "password": password, "public_key": public_key}))

    def start_p2p_listener(self):
        try:
            self.p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.p2p_socket.bind(('0.0.0.0', 0)); self.p2p_port = self.p2p_socket.getsockname()[1]; self.p2p_socket.listen(10)
            threading.Thread(target=self._p2p_accept_loop, daemon=True).start()
        except: pass

    def _p2p_accept_loop(self):
        while self.running:
            try:
                sock, addr = self.p2p_socket.accept()
                threading.Thread(target=self._handle_peer_connection, args=(sock, addr), daemon=True).start()
            except: break

    def _handle_peer_connection(self, sock, addr):
        peer = None
        try:
            while self.running:
                msg = self._recv_packet(sock)
                if not msg: break
                peer = msg.sender
                if not peer or peer == "unknown": continue
                if msg.msg_type == MessageType.P2P_HELLO.value:
                    if self.session_manager.verify_peer_handshake(peer, msg.payload["pub_key"], msg.payload["signature"], msg.payload["cert"]):
                        is_initiator = (peer in self.peer_sessions and self.peer_sessions[peer]["socket"] == sock)
                        if not is_initiator:
                            h_data = self.session_manager.get_handshake_data(peer)
                            self.session_manager.process_peer_handshake(peer, msg.payload["pub_key"])
                            self._send_packet(sock, Message(MessageType.P2P_HELLO.value, self.username, h_data))
                            self.peer_sessions[peer] = {"socket": sock}; print(f"[*] Sessão P2P com {peer} estabelecida (recetor).")
                        else:
                            self.session_manager.process_peer_handshake(peer, msg.payload["pub_key"])
                            print(f"[*] Sessão P2P com {peer} estabelecida (iniciador).")
                        if peer in self.pending_chats:
                            txt = self.pending_chats.pop(peer); print(f"[*] A enviar mensagem pendente para {peer}...")
                            payload = self.session_manager.encrypt_for_peer(peer, txt)
                            if payload: self._send_packet(sock, Message(MessageType.P2P_MSG.value, self.username, payload))
                elif msg.msg_type == MessageType.P2P_MSG.value:
                    text = self.session_manager.decrypt_from_peer(peer, msg.payload)
                    if text: print(f"\n[{peer}]: {text}")
                elif msg.msg_type == MessageType.RATCHET_CONTRIBUTION.value:
                    new_key, reply = self.session_manager.verify_and_apply_ratchet(peer, msg.payload["salt_contribution"], msg.payload["signature"])
                    if new_key:
                        self.session_manager.active_sessions[peer] = new_key; print(f"[*] Ratchet P2P concluído com {peer}.")
                        if reply: self._send_packet(sock, Message(MessageType.RATCHET_CONTRIBUTION.value, self.username, reply))
        except: pass
        finally:
            if peer: 
                with self.global_lock:
                    if peer in self.peer_sessions and self.peer_sessions[peer]["socket"] == sock: del self.peer_sessions[peer]
            sock.close()

    def connect_to_peer(self, username, ip, port):
        try:
            print(f"[*] A tentar ligar a {username} em {ip}:{port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(5); sock.connect((ip, int(port)))
            with self.global_lock: self.peer_sessions[username] = {"socket": sock}
            h_data = self.session_manager.get_handshake_data(username)
            self._send_packet(sock, Message(MessageType.P2P_HELLO.value, self.username, h_data))
            threading.Thread(target=self._handle_peer_connection, args=(sock, (ip, port)), daemon=True).start()
        except Exception as e: print(f"[!] Erro ao ligar a {username}: {e}")

    def _server_receive_loop(self):
        while self.running:
            try:
                msg = self._recv_packet(self.server_socket)
                if not msg: break
                if msg.msg_type == MessageType.RESPONSE.value:
                    status, texto = msg.payload.get("status"), msg.payload.get("message") or ""
                    if status == "success":
                        if "room_name" in msg.payload:
                            room = msg.payload["room_name"]
                            if room in self.session_manager.group_states:
                                state = self.session_manager.group_states[room]
                                if "members" in msg.payload: state["members_cache"] = msg.payload["members"]
                                if "total_leaves" in msg.payload: state["total_leaves"] = msg.payload["total_leaves"]
                                if "public_tree" in msg.payload: state["tree_pub_keys"] = {int(k): base64.b64decode(v) for k,v in msg.payload["public_tree"].items()}
                                print(f"[*] Metadados do grupo {room} sincronizados.")
                        if "Login OK" in texto:
                            self.username = msg.payload["username"]; self.session_manager.set_username(self.username)
                            if msg.payload.get("salt"):
                                salt = base64.b64decode(msg.payload["salt"]); self.session_manager.set_salt(salt)
                                if self.session_manager._temp_password: self.iden_kdf, _ = derive_key_PBKDF2HMAC(self.session_manager._temp_password, salt)
                            if not self.session_manager.load_identity_keys(self.iden_kdf, self.username):
                                print("[!] Erro: Falha ao carregar chaves."); self.running = False; return
                            for gk in msg.payload.get("group_keys", []): self.session_manager.process_key_package(gk["room_name"], gk["epoch"], gk["encrypted_blob"], self.iden_kdf)
                            print(f"\n[*] SUCESSO: {texto}"); self.should_rotate_offline_key = True
                            self._send_packet(self.server_socket, Message(MessageType.OFFLINE_STORE.value, self.username, {"action": "get"}))
                        else: print(f"\n[*] SUCESSO: {texto}")
                    else: print(f"\n[*] ERRO: {texto}")
                elif msg.msg_type == MessageType.IP_RESPONSE.value:
                    target, purpose = msg.payload.get('target_user'), msg.payload.get('purpose', '')
                    if purpose.startswith("group_create:"):
                        room = purpose.split(":", 1)[1]
                        if room in self.pending_group_actions:
                            p = self.pending_group_actions[room]
                            if msg.payload.get("status") == "success" and msg.payload.get("encryption_key"):
                                p["member_keys"].append({"username": target, "enc_pub_key": msg.payload["encryption_key"]})
                            else: print(f"[!] Erro: {target} offline. Grupo cancelado."); del self.pending_group_actions[room]; continue
                            if len(p["member_keys"]) == len(p["members"]):
                                all_m = [{"username": self.username, "enc_pub_key": base64.b64encode(self.session_manager.get_encryption_key_raw()).decode('utf-8')}] + p["member_keys"]
                                init_p = self.session_manager.initialize_tree_as_creator(room, all_m, self.iden_kdf)
                                if init_p: init_p["members"] = [m["username"] for m in all_m]; self._send_packet(self.server_socket, Message(MessageType.GROUP_INIT.value, self.username, init_p))
                                del self.pending_group_actions[room]
                    elif purpose.startswith("group_add:"):
                        room = purpose.split(":", 1)[1]
                        if msg.payload.get("encryption_key"):
                            add_p = self.session_manager.add_member_to_tree(room, target, msg.payload["encryption_key"], self.iden_kdf)
                            if add_p: self._send_packet(self.server_socket, Message(MessageType.GROUP_ADD_MEMBER.value, self.username, add_p))
                    else:
                        ip, port = msg.payload.get('ip'), msg.payload.get('port')
                        if ip: self.connect_to_peer(target, ip, port)
                        elif target in self.pending_chats:
                            print(f"[*] {target} está offline. A guardar mensagem segura...")
                            enc = self.session_manager.encrypt_offline(msg.payload.get("encryption_key"), self.pending_chats.pop(target))
                            if enc: self._send_packet(self.server_socket, Message(MessageType.OFFLINE_STORE.value, self.username, {"action": "store", "recipient": target, "content": enc["content"], "nonce": enc["nonce"], "tag": enc["tag"], "ephemeral_key": enc["ephemeral_key"]}))
                elif msg.msg_type == MessageType.GROUP_KEY_PACKAGE.value:
                    if self.session_manager.process_key_package(msg.payload["room_name"], msg.payload["epoch"], msg.payload["encrypted_blob"], self.iden_kdf):
                        self._send_packet(self.server_socket, Message(MessageType.GROUP_INFO.value, self.username, {"room_name": msg.payload["room_name"]}))
                elif msg.msg_type == MessageType.GROUP_UPDATE.value: self.session_manager.process_tree_update(msg.payload["room_name"], msg.payload, self.iden_kdf)
                elif msg.msg_type == MessageType.GROUP_MSG.value:
                    txt = self.session_manager.decrypt_from_group(msg.payload["room_name"], msg.payload["epoch"], msg.payload)
                    if txt: print(f"\n[GRUPO][{msg.payload['room_name']}][{msg.sender}]: {txt}")
                elif msg.msg_type == "offline_messages":
                    for m in msg.payload.get("messages", []): print(f"\n[OFFLINE][{m['sender']}]: {self.session_manager.decrypt_offline(m)}")
                    for gm in msg.payload.get("group_messages", []):
                        t = self.session_manager.decrypt_from_group(gm["room_name"], gm["epoch"], gm)
                        if t: print(f"\n[OFFLINE-GRUPO][{gm['room_name']}][{gm['sender']}]: {t}")
                    if self.should_rotate_offline_key and self.iden_kdf:
                        self._send_packet(self.server_socket, Message(MessageType.UPDATE_KEYS.value, self.username, {"encryption_key": base64.b64encode(self.session_manager.rotate_encryption_key(self.iden_kdf)).decode('utf-8')}))
                        self.should_rotate_offline_key = False
                elif msg.msg_type == MessageType.USERS_LIST.value: print(f"[*] Online: {msg.payload.get('users')}")
                elif msg.msg_type == MessageType.GROUP_LIST.value: print(f"[*] Teus Grupos: {msg.payload.get('groups')}")
            except Exception as e: print(f"[!] Erro no loop de receção: {e}"); traceback.print_exc()

    def _initiate_ratchet(self, peer: str):
        print(f"[*] A iniciar Ratchet P2P com {peer}...")
        contrib = self.session_manager.generate_ratchet_contribution(peer)
        if peer in self.peer_sessions: self._send_packet(self.peer_sessions[peer]["socket"], Message(MessageType.RATCHET_CONTRIBUTION.value, self.username, contrib))

    def stop(self): self.running = False; self.server_socket.close()

    def run_cli(self):
        print("\n=== SECURE P2P CHAT (v12.2) ===")
        while self.running:
            try:
                raw = input(f"[{self.username or 'Anonimo'}] > ").strip()
                if not raw: continue
                parts = raw.split(" ", 2); cmd = parts[0].lower()
                if cmd == "/register" and len(parts) == 3:
                    u, p = parts[1], parts[2]; self.iden_kdf, salt = derive_key_PBKDF2HMAC(p); pub = self.session_manager.load_or_generate_identity_keys(self.iden_kdf, u)
                    self._send_packet(self.server_socket, Message(MessageType.REGISTER.value, u, {"username": u, "password": base64.b64encode(self.iden_kdf).decode('utf-8'), "public_key": pub, "certificate": self.session_manager.get_certificate(), "encryption_key": base64.b64encode(self.session_manager.get_encryption_key_raw()).decode('utf-8'), "salt": base64.b64encode(salt).decode('utf-8')}))
                elif cmd == "/login" and len(parts) == 3:
                    u, p = parts[1], parts[2]; self.session_manager.set_password(p); self.iden_kdf = None
                    p_p = os.path.join(self.session_manager.data_dir, f"{u}_pub.pem")
                    if os.path.exists(p_p):
                        with open(p_p, "rb") as f: self.login(u, public_key=base64.b64encode(f.read()).decode('utf-8'))
                    else: self.login(u, password=p)
                elif cmd == "/chat" and len(parts) > 2:
                    t, tx = parts[1], parts[2]
                    if t in self.peer_sessions:
                        enc = self.session_manager.encrypt_for_peer(t, tx)
                        if enc:
                            print(f"[*] A enviar mensagem para {t}...");
                            self._send_packet(self.peer_sessions[t]["socket"], Message(MessageType.P2P_MSG.value, self.username, enc))
                            cnt = self.message_counts.get(t, 0) + 1; self.message_counts[t] = cnt
                            if cnt % 5 == 0: self._initiate_ratchet(t)
                    else: self.pending_chats[t] = tx; self._send_packet(self.server_socket, Message(MessageType.GET_IP.value, self.username, {"target_user": t}))
                elif cmd == "/group" and len(parts) > 1:
                    sc = parts[1].lower(); args = parts[2] if len(parts) > 2 else ""
                    if sc == "create" and args:
                        gp = [m for m in args.split(" ") if m]
                        if len(gp) < 2: continue
                        gn, others = gp[0], [m for m in gp[1:] if m != self.username]; print(f"[*] A criar grupo '{gn}'..."); self.pending_group_actions[gn] = {"type": "create", "members": others, "member_keys": []}
                        for m in others: self._send_packet(self.server_socket, Message(MessageType.GET_IP.value, self.username, {"target_user": m, "purpose": f"group_create:{gn}"}))
                    elif sc == "msg" and args:
                        r_p = args.split(" ", 1)
                        if len(r_p) == 2:
                            enc = self.session_manager.encrypt_for_group(r_p[0], r_p[1])
                            if enc: self._send_packet(self.server_socket, Message(MessageType.GROUP_MSG.value, self.username, enc))
                    elif sc == "add" and args:
                        a_p = args.split(" "); 
                        if len(a_p) == 2: self._send_packet(self.server_socket, Message(MessageType.GET_IP.value, self.username, {"target_user": a_p[1], "purpose": f"group_add:{a_p[0]}"}))
                    elif sc == "list": self._send_packet(self.server_socket, Message(MessageType.GROUP_LIST.value, self.username, {}))
                    elif sc == "info": self._send_packet(self.server_socket, Message(MessageType.GROUP_INFO.value, self.username, {"room_name": args.strip()}))
                elif cmd == "/list": self._send_packet(self.server_socket, Message(MessageType.GET_USERS.value, self.username, {}))
                elif cmd == "/exit": self.running = False; break
            except EOFError: break
            except Exception as e: print(f"[!] Erro no CLI: {e}")
        self.stop()

if __name__ == "__main__":
    client = ChatClient(server_host=input("IP [localhost]: ") or "localhost")
    if client.connect(): client.run_cli()
