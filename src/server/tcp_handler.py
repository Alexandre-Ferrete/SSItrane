"""Tratamento de uma ligação TCP individual de cliente.

Esta classe contém a lógica de parsing, routing de comandos e geração de respostas tipadas.
"""

import json
import logging
import base64
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple

from protocol.messages import Message, MessageType

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from crypto import symmetric

logger = logging.getLogger(__name__)


def _sec_ok(msg: str):
    logger.log(25, "[SEC] ✓ %s", msg)   # SECURITY level


def _sec_warn(msg: str):
    logger.warning("[SEC] ⚠ %s", msg)


def _sec_err(msg: str):
    logger.error("[SEC] ✗ %s", msg)


class ClientHandler:
    """Gere a comunicação com um único cliente TCP."""

    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server
        self.address = writer.get_extra_info("peername")
        self.username: Optional[str] = None
        self.running = False
        self.device_id: Optional[int] = None      # ← inicializar aqui
        self.nonce: Optional[str] = None          # ← idem
        self.require_new_device: bool = False     # ← idem

        self.tx_key: Optional[bytes] = None
        self.rx_key: Optional[bytes] = None

    async def handle(self):
        self.running = True
        try:
            # --- START HANDSHAKE ---
            if not await self._perform_handshake():
                logger.error(f"Handshake falhou com {self.address}. A encerrar.")
                return

            while self.running:
                message_text = await self._receive()
                if message_text is None:
                    break

                request = self._parse_request(message_text)
                response_message, auth_user, should_close = await self.process_command(request)

                if auth_user:
                    self.username = auth_user

                await self.send_message(response_message)

                if should_close:
                    break
        finally:
            await self._handle_disconnect()

    async def _perform_handshake(self) -> bool:
        """Estabelece canal seguro com o cliente (X25519 ECDH + Ed25519)."""
        logger.debug("Handshake iniciado com %s", self.address)
        try:
            # 1. Gerar chave efémera X25519 do servidor
            server_eph_priv = x25519.X25519PrivateKey.generate()
            server_eph_pub = server_eph_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # 2. Assinar a chave efémera com a identidade do servidor (Ed25519)
            signature = self.server.ca_priv_key.sign(server_eph_pub)

            # 3. Enviar SERVER_HELLO (em plaintext para iniciar)
            server_hello = Message(
                msg_type=MessageType.SERVER_HELLO.value,
                sender="server",
                payload={
                    "pub_key": base64.b64encode(server_eph_pub).decode('utf-8'),
                    "signature": base64.b64encode(signature).decode('utf-8')
                }
            )
            await self._send_raw(server_hello.to_json())

            # 4. Receber CLIENT_HELLO
            client_hello_raw = await self._receive_raw()
            if not client_hello_raw:
                return False

            client_hello = Message.from_json(client_hello_raw)
            if client_hello.msg_type != MessageType.CLIENT_HELLO.value:
                return False

            client_eph_pub_raw = base64.b64decode(client_hello.payload.get("pub_key"))
            client_eph_pub = x25519.X25519PublicKey.from_public_bytes(client_eph_pub_raw)

            # 5. Derivar segredo partilhado
            shared_secret = server_eph_priv.exchange(client_eph_pub)

            # 6. Derivar Master Key
            hkdf_master = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"ServerClientSession"
            )
            master_key = hkdf_master.derive(shared_secret)

            # 7. Derivar Chaves Direcionais para o Ratchet
            self.tx_key = HKDF(hashes.SHA256(), 32, None, b"ServerToClient").derive(master_key)
            self.rx_key = HKDF(hashes.SHA256(), 32, None, b"ClientToServer").derive(master_key)

            _sec_ok(f"HANDSHAKE_OK  protocolo=X25519+AES-256-GCM+Ratchet  addr={self.address}")
            return True
        except Exception as e:
            _sec_err(f"HANDSHAKE_FAIL  addr={self.address}  erro={e!r}")
            return False

    async def _send_raw(self, message_text: str):
        data = message_text.encode('utf-8')
        header = len(data).to_bytes(4, byteorder="big")
        self.writer.write(header + data)
        await self.writer.drain()

    async def _receive_raw(self) -> Optional[str]:
        try:
            header = await self.reader.readexactly(4)
            msg_len = int.from_bytes(header, byteorder="big")
            data = await self.reader.readexactly(msg_len)
            return data.decode().strip()
        except Exception:
            return None

    async def send_message(self, message: Message):
        """Envia mensagem (cifrada se a sessão estiver ativa). Aplica Ratchet TX."""
        json_msg = message.to_json()
        if self.tx_key:
            ciphertext, nonce, tag = symmetric.encrypt(self.tx_key, json_msg.encode('utf-8'))
            self.tx_key = HKDF(hashes.SHA256(), 32, None, b"Ratchet").derive(self.tx_key)
            encrypted_payload = {
                "content": base64.b64encode(ciphertext).decode('utf-8'),
                "nonce":   base64.b64encode(nonce).decode('utf-8'),
                "tag":     base64.b64encode(tag).decode('utf-8')
            }
            wrapped_msg = Message(msg_type="encrypted", sender="server", payload=encrypted_payload)
            await self._send_raw(wrapped_msg.to_json())
        else:
            await self._send_raw(json_msg)

    async def _receive(self) -> Optional[str]:
        """Recebe mensagem (desencripta se a sessão estiver ativa). Aplica Ratchet RX."""
        raw_text = await self._receive_raw()
        if not raw_text or not self.rx_key:
            return raw_text

        try:
            envelope = Message.from_json(raw_text)
            if envelope.msg_type != "encrypted": return raw_text
            payload = envelope.payload
            ciphertext = base64.b64decode(payload["content"])
            nonce = base64.b64decode(payload["nonce"])
            tag = base64.b64decode(payload["tag"])
            plaintext = symmetric.decrypt(self.rx_key, ciphertext, nonce, tag)
            self.rx_key = HKDF(hashes.SHA256(), 32, None, b"Ratchet").derive(self.rx_key)
            return plaintext.decode('utf-8')
        except Exception as e:
            _sec_err(f"DECRYPT_FAIL  addr={self.address}  motivo='ratchet_desinc_ou_adulteracao'  erro={e!r}")
            return None

    def _parse_request(self, message_text: str) -> Dict[str, Any]:
        try:
            raw = json.loads(message_text)
            t = raw.get("msg_type") or raw.get("type")
            s = raw.get("sender")
            d = raw.get("payload") or raw.get("data") or {}
            return {"type": t, "sender": s, "data": d}
        except Exception as e:
            logger.error(f"Erro no parsing: {e}")
            return {"type": None, "sender": None, "data": {}}

    def _build_response(self, msg_type: MessageType, sender: str, payload: Dict[str, Any]) -> Message:
        return Message(msg_type=msg_type.value, sender=sender, payload=payload)

    def _ensure_bytes(self, data) -> bytes:
        if not data: return b""
        if isinstance(data, bytes): return data
        if isinstance(data, str):
            try: return base64.b64decode(data)
            except: return data.encode("utf-8")
        return b""

    def _is_ed25519_key(self, key_data: bytes) -> bool:
        try:
            key = serialization.load_pem_public_key(key_data)
            return isinstance(key, Ed25519PublicKey)
        except: return False

    def _validate_certificate(self, cert_data: bytes, public_key_data: bytes) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            public_key = serialization.load_pem_public_key(public_key_data)
            cert_pub_pem = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            if cert_pub_pem != pub_pem: return False
            # Verify the certificate was signed by this server's CA
            self.server.ca_pub_key.verify(cert.signature, cert.tbs_certificate_bytes)
            # Validate time window (not_valid_before returns naive UTC in cryptography 41.x)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            if now < cert.not_valid_before or now > cert.not_valid_after: return False
            return True
        except: return False

    async def process_command(self, request: Dict[str, Any]):
        cmd = (request.get("type") or "").lower()
        data = request.get("data", {}) or {}
        sender = request.get("sender") or self.username or "server"

        # 1. REGISTO
        if cmd == MessageType.REGISTER.value:
            username = data.get("username") or sender
            password = data.get("password")
            public_key_pem = data.get("public_key")
            encryption_key = data.get("encryption_key")
            salt_b64 = data.get("salt")
            if not username or not password or not public_key_pem:
                _sec_warn(f"REGISTER_FAIL  addr={self.address}  motivo='dados_incompletos'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Dados incompletos"}), None, False
            if self.server.storage.get_user(username):
                _sec_warn(f"REGISTER_FAIL  user={username!r}  addr={self.address}  motivo='utilizador_ja_existe'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Utilizador já existe"}), None, False

            public_key_bytes = self._ensure_bytes(public_key_pem)
            if not self._is_ed25519_key(public_key_bytes):
                _sec_err(f"REGISTER_FAIL  user={username!r}  addr={self.address}  motivo='chave_nao_e_ed25519'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Chave pública deve ser Ed25519"}), None, False

            try:
                user_pub_key = serialization.load_pem_public_key(public_key_bytes)
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
                issuer  = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureP2PChat-CA")])
                cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(user_pub_key)
                    .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc))
                    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .sign(self.server.ca_priv_key, algorithm=None))
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            except Exception as e:
                _sec_err(f"CERT_SIGN_FAIL  user={username!r}  addr={self.address}  erro={e!r}")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": f"Erro CA: {e}"}), None, False

            salt_bytes = base64.b64decode(salt_b64) if salt_b64 else None
            enc_key_bytes = self._ensure_bytes(encryption_key) if encryption_key else None
            self.server.storage.create_user(username, password)
            self.server.storage.add_device(username, public_key_bytes, cert_pem, salt_bytes, encryption_key=enc_key_bytes)
            _sec_ok(f"REGISTER_OK  user={username!r}  addr={self.address}  cert=X.509/Ed25519/365d")
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": "Registo OK", "certificate": base64.b64encode(cert_pem).decode('utf-8')}), None, False

        # 2. LOGIN
        if cmd == MessageType.AUTH.value:
            username = data.get("username")
            password = data.get("password")
            p2p_port = int(data.get("p2p_port", 0) or 0)
            public_key = data.get("public_key")
            if not username:
                _sec_warn(f"AUTH_FAIL  addr={self.address}  motivo='username_ausente'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Username obrigatório"}), None, False
            user = self.server.storage.get_user(username)
            if not user:
                _sec_warn(f"AUTH_FAIL  user={username!r}  addr={self.address}  motivo='utilizador_nao_existe'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não encontrado"}), None, False

            public_key_bytes = self._ensure_bytes(public_key) if public_key else None
            existing_device = self.server.storage.get_device(username, public_key_bytes) if public_key_bytes else None

            if existing_device:
                if password and user.get("password_hash") != password:
                    _sec_warn(f"AUTH_FAIL  user={username!r}  addr={self.address}  motivo='password_errada'")
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Password errada"}), None, False
                self.device_id = existing_device["id"]
                await self.server.online_users.add_online_user(username, self.address[0], p2p_port, self)
                nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
                self.nonce = nonce
                salt = existing_device.get("salt")
                self.server.storage.update_last_login(self.device_id)
                _sec_ok(f"AUTH_OK  user={username!r}  addr={self.address}  device_id={self.device_id}  p2p_port={p2p_port}")

                # TreeKEM KeyPackages — fetch, deliver, then delete to prevent
                # stale-key InvalidTag on future logins after key rotation.
                packages = self.server.storage.get_key_packages_for_user(username)
                pkg_list = []
                for p in packages:
                    try:
                        pkg_list.append({
                            "room_name": p["group_name"],
                            "epoch": p["epoch"],
                            "encrypted_blob": json.loads(p["encrypted_blob"].decode('utf-8')),
                        })
                    except:
                        pass
                for p in packages:
                    self.server.storage.delete_key_packages_for_user(username, p["group_name"])

                return self._build_response(MessageType.RESPONSE, "server", {
                    "status": "success", "message": "Login OK", "username": username, "device_id": self.device_id, "nonce": nonce,
                    "salt": base64.b64encode(salt).decode('utf-8') if salt else None,
                    "encryption_key": base64.b64encode(existing_device["encryption_key"]).decode('utf-8') if existing_device.get("encryption_key") else None,
                    "group_keys": pkg_list
                }), username, False

            # Novo dispositivo
            if password and user.get("password_hash") != password:
                _sec_warn(f"AUTH_FAIL  user={username!r}  addr={self.address}  motivo='password_errada_novo_disp'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Password errada"}), None, False
            await self.server.online_users.add_online_user(username, self.address[0], p2p_port, self)
            self.nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
            self.require_new_device = True
            _sec_ok(f"AUTH_OK  user={username!r}  addr={self.address}  novo_dispositivo=True")
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": "Login OK - Novo disp", "username": username, "require_new_device": True, "nonce": self.nonce}), username, False

        # 3. GET_IP
        if cmd == MessageType.GET_IP.value:
            target = data.get("target_user")
            purpose = data.get("purpose")
            addr = await self.server.online_users.get_user_address(target)
            devices = self.server.storage.get_devices(target)
            pub_b64, enc_b64 = None, None
            if devices:
                pub_b64 = base64.b64encode(devices[0]["public_key"]).decode('utf-8')
                if devices[0].get("encryption_key"): enc_b64 = base64.b64encode(devices[0]["encryption_key"]).decode('utf-8')
            payload = {"target_user": target, "status": "success" if addr else "offline", "public_key": pub_b64, "encryption_key": enc_b64}
            if addr: payload["ip"], payload["port"] = addr
            if purpose: payload["purpose"] = purpose
            return self._build_response(MessageType.IP_RESPONSE, "server", payload), None, False

        # 4. UPDATE_KEYS
        if cmd == MessageType.UPDATE_KEYS.value:
            if not self.username:
                _sec_warn(f"UNAUTHORIZED  cmd={cmd!r}  addr={self.address}  motivo='nao_autenticado'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não auth"}), None, False
            enc_key = data.get("encryption_key")
            if not enc_key: return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Falta chave"}), None, False
            self.server.storage.update_device_encryption_key(self.device_id, self._ensure_bytes(enc_key))
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": "Chave atualizada"}), None, False

        # 5. GET_USERS
        if cmd == MessageType.GET_USERS.value:
            if not self.username:
                _sec_warn(f"UNAUTHORIZED  cmd={cmd!r}  addr={self.address}  motivo='nao_autenticado'")
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não auth"}), None, False
            users = await self.server.online_users.list_online_users()
            return self._build_response(MessageType.USERS_LIST, "server", {"users": users}), None, False

        # 6. TREEKEM GROUPS
        if cmd == MessageType.GROUP_CREATE.value:
            room = data.get("room_name")
            member_list = data.get("members", [])
            if not room or not member_list:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Dados incompletos"}), None, False
            member_keys = []
            for uname in member_list:
                devices = self.server.storage.get_devices(uname)
                enc_b64 = None
                if devices and devices[0].get("encryption_key"):
                    enc_b64 = base64.b64encode(devices[0]["encryption_key"]).decode('utf-8')
                member_keys.append({"username": uname, "encryption_key": enc_b64})
            return self._build_response(MessageType.GROUP_CREATE, "server", {"status": "success", "room_name": room, "member_keys": member_keys}), None, False

        if cmd == MessageType.GROUP_INIT.value:
            room = data.get("room_name")
            total = data.get("total_leaves")
            tree = data.get("public_tree", {})
            pkgs = data.get("key_packages", [])
            m_list = data.get("members", [])
            if not self.server.storage.create_group(room, self.username, total):
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Existe"}), None, False
            for idx, pub in tree.items(): self.server.storage.store_tree_node(room, int(idx), base64.b64decode(pub))
            for i, u in enumerate(m_list): self.server.storage.add_group_member(room, u, total + i)
            for kp in pkgs:
                u, blob = kp.get("username"), kp.get("encrypted_blob")
                if u and blob:
                    self.server.storage.store_group_key_package(room, 0, u, json.dumps(blob).encode('utf-8'))
                    h = await self.server.online_users.get_user_socket(u)
                    if h:
                        try: await h.send_message(Message(MessageType.GROUP_KEY_PACKAGE.value, "server", {"room_name": room, "epoch": 0, "encrypted_blob": blob}))
                        except: pass
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": f"Grupo {room} OK"}), None, False

        if cmd == MessageType.GROUP_MSG.value:
            room, epoch = data.get("room_name"), data.get("epoch")
            content, nonce, tag = data.get("content"), data.get("nonce"), data.get("tag")
            if not self.server.storage.is_group_member(room, self.username):
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não é membro"}), None, False
            await self.server.router.broadcast_to_room(room, self.username, epoch, content, nonce, tag)
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": "Enviada"}), None, False

        if cmd == MessageType.GROUP_LIST.value:
            groups = self.server.storage.list_user_groups(self.username)
            return self._build_response(MessageType.GROUP_LIST, "server", {"groups": groups}), None, False

        if cmd == MessageType.GROUP_INFO.value:
            room = data.get("room_name")
            g = self.server.storage.get_group(room)
            if not g: return self._build_response(MessageType.RESPONSE, "server", {"status": "error"}), None, False
            members = self.server.storage.get_group_members(room, True)
            nodes = self.server.storage.get_tree_nodes(room)
            pub_tree = {str(n["node_index"]): base64.b64encode(n["public_key"]).decode('utf-8') for n in nodes}
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "room_name": room, "created_by": g["created_by"], "epoch": g["epoch"], "total_leaves": g["total_leaves"], "members": [m["username"] for m in members], "public_tree": pub_tree}), None, False

        if cmd == MessageType.GROUP_UPDATE.value:
            room, epoch = data.get("room_name"), data.get("new_epoch")
            pub_keys, pkgs = data.get("public_keys", {}), data.get("key_packages", [])
            if not self.server.storage.is_group_member(room, self.username): return self._build_response(MessageType.RESPONSE, "server", {"status": "error"}), None, False
            self.server.storage.update_group_epoch(room, epoch)
            for i, p in pub_keys.items(): self.server.storage.store_tree_node(room, int(i), base64.b64decode(p))
            for kp in pkgs: self.server.storage.store_group_key_package(room, epoch, kp["username"], json.dumps(kp["encrypted_blob"]).encode('utf-8'))
            mems = self.server.storage.get_group_members(room, True)
            upd = Message(MessageType.GROUP_UPDATE.value, self.username, data)
            for m in mems:
                if m["username"] == self.username: continue
                h = await self.server.online_users.get_user_socket(m["username"])
                if h:
                    try: await h.send_message(upd)
                    except: pass
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success"}), None, False

        if cmd == MessageType.GROUP_ADD_MEMBER.value:
            room = data.get("room_name")
            new_user = data.get("username")
            epoch = data.get("epoch")
            pub_tree = data.get("public_tree", {})
            key_packages = data.get("key_packages", [])
            member_key_packages = data.get("member_key_packages", [])
            total_leaves = data.get("total_leaves", 0)

            if not self.server.storage.is_group_member(room, self.username):
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não é membro"}), None, False

            # Add new member
            new_leaf = key_packages[0].get("leaf_index", total_leaves) if key_packages else total_leaves
            self.server.storage.add_group_member(room, new_user, new_leaf)
            self.server.storage.add_room_member(room, new_user)

            # Update public tree nodes and epoch
            for idx, pub in pub_tree.items():
                self.server.storage.store_tree_node(room, int(idx), base64.b64decode(pub))
            if epoch is not None:
                self.server.storage.update_group_epoch(room, epoch)

            # Deliver key package to the new user
            for kp in key_packages:
                target, blob = kp.get("username"), kp.get("encrypted_blob")
                if target and blob:
                    self.server.storage.store_group_key_package(room, epoch or 0, target, json.dumps(blob).encode('utf-8'))
                    h = await self.server.online_users.get_user_socket(target)
                    if h:
                        try: await h.send_message(Message(MessageType.GROUP_KEY_PACKAGE.value, "server", {"room_name": room, "epoch": epoch or 0, "encrypted_blob": blob}))
                        except: pass

            # Deliver updated path secrets to existing members
            for mkp in member_key_packages:
                target, blob = mkp.get("username"), mkp.get("encrypted_blob")
                if target and blob:
                    self.server.storage.store_group_key_package(room, epoch or 0, target, json.dumps(blob).encode('utf-8'))
                    h = await self.server.online_users.get_user_socket(target)
                    if h:
                        try: await h.send_message(Message(MessageType.GROUP_KEY_PACKAGE.value, "server", {"room_name": room, "epoch": epoch or 0, "encrypted_blob": blob}))
                        except: pass

            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": f"{new_user} adicionado ao grupo {room}"}), None, False

        if cmd == MessageType.GROUP_REMOVE_MEMBER.value:
            room = data.get("room_name")
            removed_user = data.get("removed_user")
            epoch = data.get("epoch")
            pub_tree = data.get("public_tree", {})
            member_key_packages = data.get("member_key_packages", [])

            group = self.server.storage.get_group(room)
            if not group:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Grupo não encontrado"}), None, False
            if group["created_by"] != self.username:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Sem permissão (apenas admin)"}), None, False

            self.server.storage.remove_group_member(room, removed_user)
            for idx, pub in pub_tree.items():
                self.server.storage.store_tree_node(room, int(idx), base64.b64decode(pub))
            if epoch is not None:
                self.server.storage.update_group_epoch(room, epoch)

            # Notify removed user if online
            rh = await self.server.online_users.get_user_socket(removed_user)
            if rh:
                try:
                    await rh.send_message(Message(MessageType.RESPONSE.value, "server", {
                        "status": "info", "message": f"Foste removido do grupo {room}", "removed_from_group": room
                    }))
                except: pass

            # Deliver updated key packages to remaining members
            mems = self.server.storage.get_group_members(room, True)
            remaining_names = [m["username"] for m in mems]
            for mkp in member_key_packages:
                target, blob = mkp.get("username"), mkp.get("encrypted_blob")
                if target and blob:
                    self.server.storage.store_group_key_package(room, epoch or 0, target, json.dumps(blob).encode('utf-8'))
                    h = await self.server.online_users.get_user_socket(target)
                    if h:
                        try:
                            await h.send_message(Message(MessageType.GROUP_KEY_PACKAGE.value, "server", {
                                "room_name": room, "epoch": epoch or 0, "encrypted_blob": blob
                            }))
                        except: pass

            # Broadcast GROUP_UPDATE so remaining members know who was removed and update co-path
            upd = Message(MessageType.GROUP_UPDATE.value, self.username, {
                "room_name": room, "epoch": epoch,
                "public_tree": data.get("public_tree", {}),
                "removed_user": removed_user, "members": remaining_names,
            })
            for m in mems:
                if m["username"] == self.username: continue
                h = await self.server.online_users.get_user_socket(m["username"])
                if h:
                    try: await h.send_message(upd)
                    except: pass

            return self._build_response(MessageType.RESPONSE, "server", {
                "status": "success", "message": f"{removed_user} removido do grupo {room}"
            }), None, False

        # 7. OFFLINE STORE
        if cmd == MessageType.OFFLINE_STORE.value:
            action = data.get("action")
            if action == "register_device":
                pub, cert, enc, salt = data.get("public_key"), data.get("certificate"), data.get("encryption_key"), data.get("salt")
                if not pub or not cert: return self._build_response(MessageType.RESPONSE, "server", {"status": "error"}), None, False
                pub_b, cert_b, enc_b = self._ensure_bytes(pub), self._ensure_bytes(cert), self._ensure_bytes(enc)
                salt_b = base64.b64decode(salt) if salt else None
                self.server.storage.add_device(self.username, pub_b, cert_b, salt_b, encryption_key=enc_b)
                device = self.server.storage.get_device(self.username, pub_b)
                self.device_id = device["id"]
                self.server.storage.update_last_login(self.device_id)
                return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "device_id": self.device_id}), None, False

            if action == "get":
                if not self.username: return self._build_response(MessageType.RESPONSE, "server", {"status": "error"}), None, False
                msgs_db = self.server.storage.get_offline_messages_by_device(self.device_id)
                msgs = []
                for m in msgs_db:
                    msgs.append({"sender": m["sender"], "content": base64.b64encode(m["content"]).decode('utf-8'), "nonce": base64.b64encode(m["nonce"]).decode('utf-8'), "tag": base64.b64encode(m["tag"]).decode('utf-8'), "ephemeral_key": base64.b64encode(m["ephemeral_key"]).decode('utf-8')})
                g_msgs_db = self.server.storage.get_group_messages_for_user(self.username)
                g_msgs = []
                for gm in g_msgs_db:
                    g_msgs.append({"room_name": gm["group_name"], "sender": gm["sender"], "epoch": gm["epoch"], "content": base64.b64encode(gm["content"]).decode('utf-8'), "nonce": base64.b64encode(gm["nonce"]).decode('utf-8'), "tag": base64.b64encode(gm["tag"]).decode('utf-8')})
                self.server.storage.clear_offline_messages_by_device(self.device_id)
                self.server.storage.clear_group_messages_for_user(self.username)
                return Message(msg_type="offline_messages", sender="server", payload={"messages": msgs, "group_messages": g_msgs}), None, False

            if action == "store":
                rec, cont, non, tag, eph = data.get("recipient"), data.get("content"), data.get("nonce"), data.get("tag"), data.get("ephemeral_key")
                if not rec or not cont: return self._build_response(MessageType.RESPONSE, "server", {"status": "error"}), None, False
                c_b, n_b, t_b, e_b = base64.b64decode(cont), base64.b64decode(non) if non else None, base64.b64decode(tag) if tag else None, base64.b64decode(eph) if eph else None
                targets = self.server.storage.get_devices(rec)
                for d in targets: self.server.storage.store_offline_message(rec, sender, c_b, n_b, t_b, device_id=d["id"], ephemeral_key=e_b)
                return self._build_response(MessageType.RESPONSE, "server", {"status": "success"}), None, False

        if cmd == MessageType.DISCONNECT.value:
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success"}), None, True

        return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": f"Desconhecido: {cmd}"}), None, False

    async def _handle_disconnect(self):
        if self.username:
            await self.server.online_users.remove_online_user(self.username)
            _sec_ok(f"DISCONNECT  user={self.username!r}  addr={self.address}")
        else:
            logger.info("Conexão encerrada (sem autenticação)  addr=%s", self.address)
        self.running = False
        await self.close()

    async def close(self):
        if not self.writer.is_closing():
            self.writer.close()
            try: await self.writer.wait_closed()
            except: pass
