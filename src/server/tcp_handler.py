"""Tratamento de uma ligação TCP individual de cliente.

Esta classe contém a lógica que antes vivia em `server.py`: parsing,
routing de comandos e geração de respostas tipadas.
"""

import json
import logging
import base64
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

from protocol.messages import Message, MessageType

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography import x509
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class ClientHandler:
    """Gere a comunicação com um único cliente TCP."""

    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server
        self.address = writer.get_extra_info("peername")
        self.username: Optional[str] = None
        self.running = False

    async def handle(self):
        self.running = True
        try:
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

    async def _receive(self) -> Optional[str]:
        try:
            header = await self.reader.readexactly(4)
            msg_len = int.from_bytes(header, byteorder="big")
            data = await self.reader.readexactly(msg_len)
            return data.decode().strip()
        except Exception:
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
        if not data:
            return b""
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            if data.startswith("-----BEGIN"):
                return data.encode("utf-8")
            try:
                return base64.b64decode(data)
            except Exception:
                return data.encode("utf-8")
        return b""

    def _is_ed25519_key(self, key_data: bytes) -> bool:
        try:
            key = load_pem_public_key(key_data)
            return isinstance(key, Ed25519PublicKey)
        except Exception:
            return False

    def _is_ed25519_certificate(self, cert_data: bytes) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            return isinstance(cert.public_key(), Ed25519PublicKey)
        except Exception:
            return False

    def _validate_certificate(self, cert_data: bytes, public_key_data: bytes) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            public_key = load_pem_public_key(public_key_data)

            if not isinstance(cert.public_key(), Ed25519PublicKey):
                logger.error("Certificado não usa Ed25519")
                return False

            cert_pub_pem = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if cert_pub_pem != pub_pem:
                logger.error("Chave pública não corresponde ao certificado")
                return False

            now = datetime.now(timezone.utc)
            cert_not_before = cert.not_valid_before_utc
            cert_not_after = cert.not_valid_after_utc
            if now < cert_not_before or now > cert_not_after:
                logger.error("Certificado expirado")
                return False

            return True
        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            return False

    async def process_command(self, request: Dict[str, Any]):
        cmd = (request.get("type") or "").lower()
        data = request.get("data", {}) or {}
        sender = request.get("sender") or self.username or "server"

        # 1. REGISTO
        if cmd == MessageType.REGISTER.value:
            username = data.get("username") or sender
            password = data.get("password")
            public_key = data.get("public_key")
            certificate = data.get("certificate")
            salt_b64 = data.get("salt")

            if not username or not password:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Username e password são obrigatórios"}), None, False

            existing_user = self.server.storage.get_user(username)
            if existing_user:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Utilizador já existe"}), None, False

            if public_key:
                logger.info(f"[*] A validar chave pública para {username}")
                public_key_bytes = self._ensure_bytes(public_key)
                if not self._is_ed25519_key(public_key_bytes):
                    logger.error(f"[!] Chave pública inválida para {username}")
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Chave pública deve ser Ed25519"}), None, False

            if certificate and public_key:
                logger.info(f"[*] A validar certificado para {username}")
                cert_bytes = self._ensure_bytes(certificate)
                pub_bytes = self._ensure_bytes(public_key)
                if not self._validate_certificate(cert_bytes, pub_bytes):
                    logger.error(f"[!] Certificado inválido para {username}")
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Certificado inválido ou não corresponde à chave pública"}), None, False

            salt_bytes = None
            if salt_b64:
                try:
                    salt_bytes = base64.b64decode(salt_b64)
                except Exception as e:
                    logger.warning(f"Salt inválido ignorado: {e}")

            public_key_bytes = self._ensure_bytes(public_key)
            cert_bytes = self._ensure_bytes(certificate)

            user_created = self.server.storage.create_user(username, password)
            if not user_created:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Falha ao criar utilizador"}), None, False

            device_added = self.server.storage.add_device(username, public_key_bytes, cert_bytes, salt_bytes)
            if not device_added:
                self.server.storage.delete_user(username)
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Falha ao registar dispositivo"}), None, False

            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": "Registo efetuado com sucesso"}), None, False

        # 2. LOGIN (AUTH)
        if cmd == MessageType.AUTH.value:
            username = data.get("username")
            password = data.get("password")
            p2p_port = int(data.get("p2p_port", 0) or 0)
            use_challenge = data.get("use_challenge", False)
            request_salt = data.get("request_salt", False)
            public_key = data.get("public_key")

            if not username:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Username é obrigatório"}), None, False

            user = self.server.storage.get_user(username)
            if user is None:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Utilizador não encontrado"}), None, False

            public_key_bytes = None
            if public_key:
                public_key_bytes = self._ensure_bytes(public_key)

            existing_device = None
            if public_key_bytes:
                existing_device = self.server.storage.get_device(username, public_key_bytes)

            if existing_device:
                if password and user.get("password_hash") != password:
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Password incorreta"}), None, False
                auth_method = "challenge" if use_challenge else "password"

                self.device_id = existing_device["id"]
                await self.server.online_users.add_online_user(username, self.address[0], p2p_port, self.writer)

                nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
                self.nonce = nonce
                self.auth_method = auth_method

                salt = existing_device.get("salt")
                salt_b64 = base64.b64encode(salt).decode('utf-8') if salt else None

                self.server.storage.update_last_login(self.device_id)

                return self._build_response(MessageType.RESPONSE, "server", {
                    "status": "success",
                    "message": "Login OK",
                    "username": username,
                    "device_id": self.device_id,
                    "nonce": nonce,
                    "salt": salt_b64,
                    "require_challenge": auth_method == "challenge"
                }), username, False

            if request_salt and not password and not use_challenge:
                return self._build_response(MessageType.RESPONSE, "server", {
                    "status": "success",
                    "message": "Novo dispositivo detetado. Faça registo ou pedido de salt."
                }), None, False

            if use_challenge:
                auth_method = "challenge"
            elif password:
                if user.get("password_hash") != password:
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Password incorreta"}), None, False
                auth_method = "password"
            else:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Credenciais incompletas"}), None, False

            await self.server.online_users.add_online_user(username, self.address[0], p2p_port, self.writer)
            nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
            self.nonce = nonce
            self.auth_method = auth_method
            self.require_new_device = True

            return self._build_response(MessageType.RESPONSE, "server", {
                "status": "success",
                "message": "Login OK - Novo dispositivo",
                "username": username,
                "require_new_device": True,
                "nonce": nonce,
                "require_challenge": auth_method == "challenge"
            }), username, False

        # 3. OBTER IP (Para P2P)
        if cmd == MessageType.GET_IP.value:
            target_user = data.get("target_user")
            address = await self.server.online_users.get_user_address(target_user)

            devices = self.server.storage.get_devices(target_user)
            pub_key_b64 = None
            if devices and len(devices) > 0:
                pub_key_bytes = devices[0].get("public_key")
                if pub_key_bytes:
                    pub_key_b64 = base64.b64encode(pub_key_bytes).decode('utf-8')

            if address:
                ip, port = address
                return self._build_response(MessageType.IP_RESPONSE, "server", {
                    "target_user": target_user,
                    "ip": ip,
                    "port": port,
                    "status": "success",
                    "public_key": pub_key_b64
                }), None, False

            return self._build_response(MessageType.IP_RESPONSE, "server", {
                "target_user": target_user,
                "ip": None,
                "port": None,
                "status": "offline",
                "public_key": pub_key_b64
            }), None, False

        # 4. LISTAR UTILIZADORES
        if cmd == MessageType.GET_USERS.value:
            if not self.username:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não autenticado"}), None, False

            users = await self.server.online_users.list_online_users()
            return self._build_response(MessageType.USERS_LIST, "server", {"users": users}), None, False

        # 5. RATCHET REQUEST — cliente pede rotação de chaves
        if cmd == MessageType.RATCHET_REQUEST.value:
            if not self.username:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não autenticado"}), None, False

            peer_username = data.get("peer")
            if not peer_username:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Peer não especificado"}), None, False

            # Gerar novo salt aleatório (32 bytes)
            new_salt = os.urandom(32)
            new_salt_b64 = base64.b64encode(new_salt).decode('utf-8')

            logger.info(f"[*] Ratchet solicitado por {self.username} para sessão com {peer_username}. A enviar salt...")

            # Montar mensagem RATCHET_SALT para ambos os clientes
            ratchet_msg = Message(
                msg_type=MessageType.RATCHET_SALT.value,
                sender="server",
                payload={
                    "salt": new_salt_b64,
                    "peer": peer_username,      # quem é o outro lado (do ponto de vista do receptor)
                    "initiator": self.username  # quem pediu o ratchet
                }
            )

            # Enviar ao peer (se estiver online)
            peer_writer = await self.server.online_users.get_user_socket(peer_username)
            if peer_writer:
                data_bytes = ratchet_msg.to_json().encode("utf-8")
                peer_writer.write(len(data_bytes).to_bytes(4, byteorder="big") + data_bytes)
                await peer_writer.drain()
                logger.info(f"[*] Salt de ratchet enviado a {peer_username}")
            else:
                logger.warning(f"[!] Peer {peer_username} não está online para receber salt de ratchet")

            # Enviar também ao iniciador (para que ambos derivem ao mesmo tempo)
            return Message(
                msg_type=MessageType.RATCHET_SALT.value,
                sender="server",
                payload={
                    "salt": new_salt_b64,
                    "peer": peer_username,
                    "initiator": self.username
                }
            ), None, False

        # 6. OFFLINE STORE
        if cmd == MessageType.OFFLINE_STORE.value:
            action = data.get("action")
            nonce_encrypted = data.get("nonce_encrypted")

            if action == "register_device":
                if not hasattr(self, 'require_new_device') or not self.require_new_device:
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não requer registo de dispositivo"}), None, False

                public_key = data.get("public_key")
                certificate = data.get("certificate")
                salt = data.get("salt")

                if not public_key or not certificate:
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Chave pública e certificado são obrigatórios"}), None, False

                public_key_bytes = self._ensure_bytes(public_key)
                cert_bytes = self._ensure_bytes(certificate)
                salt_bytes = None
                if salt:
                    try:
                        salt_bytes = base64.b64decode(salt)
                    except:
                        pass

                added = self.server.storage.add_device(self.username, public_key_bytes, cert_bytes, salt_bytes)
                if not added:
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Falha ao registar dispositivo"}), None, False

                device = self.server.storage.get_device(self.username, public_key_bytes)
                self.device_id = device["id"]
                self.require_new_device = False
                self.server.storage.update_last_login(self.device_id)

                return self._build_response(MessageType.RESPONSE, "server", {
                    "status": "success",
                    "message": "Dispositivo registado",
                    "device_id": self.device_id
                }), None, False

            if action == "get":
                if not hasattr(self, 'username') or not self.username or self.username != sender:
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Não autenticado"}), None, False

                device = self.server.storage.get_device_by_id(self.device_id) if hasattr(self, 'device_id') and self.device_id else None

                if device and hasattr(self, 'auth_method') and self.auth_method == "challenge":
                    pub_key_data = device.get("public_key")
                    if pub_key_data:
                        pub_key = load_pem_public_key(pub_key_data)
                        try:
                            pub_key.verify(base64.b64decode(nonce_encrypted), self.nonce.encode('utf-8'))
                        except Exception as e:
                            logger.error(f"Nonce verification failed: {e}")
                            return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Nonce inválido"}), None, False

                mensagens_db = self.server.storage.get_offline_messages_by_device(self.device_id)
                mensagens_para_enviar = []

                for m in mensagens_db:
                    def ensure_str(data):
                        if data is None:
                            return ""
                        if isinstance(data, bytes):
                            try:
                                return data.decode('utf-8')
                            except UnicodeDecodeError:
                                return base64.b64encode(data).decode('utf-8')
                        return str(data)

                    payload_msg = {
                        "sender": m["sender"],
                        "content": ensure_str(m["content"]),
                        "nonce": ensure_str(m["nonce"]),
                        "tag": ensure_str(m["tag"])
                    }
                    mensagens_para_enviar.append(payload_msg)

                self.server.storage.clear_offline_messages_by_device(self.device_id)

                return Message(
                    msg_type="offline_messages",
                    sender="server",
                    payload={"messages": mensagens_para_enviar}
                ), None, False

            elif action == "store":
                recipient = data.get("recipient")
                content = data.get("content")
                nonce = data.get("nonce")
                tag = data.get("tag")

                if not recipient or not content:
                    return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Dados insuficientes"}), None, False

                target_devices = self.server.storage.get_devices(recipient)
                for device in target_devices:
                    self.server.storage.store_offline_message(
                        recipient, sender,
                        content.encode() if isinstance(content, str) else content,
                        nonce.encode() if nonce and isinstance(nonce, str) else nonce,
                        tag.encode() if tag and isinstance(tag, str) else tag,
                        device_id=device["id"]
                    )

                return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": "Mensagem guardada offline"}), None, False

            else:
                return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": "Ação offline desconhecida"}), None, False

        # 7. DESCONECTAR
        if cmd == MessageType.DISCONNECT.value:
            return self._build_response(MessageType.RESPONSE, "server", {"status": "success", "message": "Desconectado"}), None, True

        return self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": f"Comando desconhecido: {cmd}"}), None, False

    async def _handle_disconnect(self):
        if self.username:
            await self.server.online_users.remove_online_user(self.username)
            self.username = None
        self.running = False
        await self.close()

    async def send_message(self, message: Message):
        data = message.to_json().encode("utf-8")
        self.writer.write(len(data).to_bytes(4, byteorder="big") + data)
        await self.writer.drain()

    async def send_error(self, error_message: str):
        await self.send_message(self._build_response(MessageType.RESPONSE, "server", {"status": "error", "message": error_message}))

    async def send_success(self, data: Dict[str, Any]):
        await self.send_message(self._build_response(MessageType.RESPONSE, "server", {"status": "success", **data}))

    async def close(self):
        if not self.writer.is_closing():
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass