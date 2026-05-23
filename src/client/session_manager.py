import os
import json
import base64
import utils.helpers as help
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID


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


class SessionManager:

    def __init__(self, username: str = None, data_dir: str = "client_data"):
        self.username = username
        self.data_dir = data_dir
        self._ensure_dir()

        # Identity Key (Ed25519 - Signatures)
        self.identity_pub_key: Optional[Ed25519PublicKey] = None
        self.identity_cert: Optional[bytes] = None

        # Static Encryption Key (X25519 - Offline Messages)
        self.encryption_priv_key: Optional[x25519.X25519PrivateKey] = None
        self.encryption_pub_key: Optional[x25519.X25519PublicKey] = None

        # Current secure sessions (AES-GCM keys)
        self.active_sessions: Dict[str, bytes] = {}

        # Cache of peer public keys (X25519)
        self.peer_public_keys: Dict[str, bytes] = {}

        # Cache of peer encryption keys (X25519) for offline messages
        self.peer_encryption_keys: Dict[str, bytes] = {}

        # Temporary storage for ephemeral keys during handshake
        self.pending_ephemeral_priv_keys: Dict[str, bytes] = {}
        self.pending_ratchet_salt: Dict[str, bytes] = {}

        self._salt = None
        self._temp_password = None

    def _ensure_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def set_username(self, username: str):
        self.username = username
        self._ensure_dir()
        print(f"[*] SessionManager configurado para: {username}")

    def set_password(self, password: str):
        self._temp_password = password

    def set_salt(self, salt):
        if isinstance(salt, bytes):
            self._salt = salt
        else:
            try:
                self._salt = base64.b64decode(salt)
            except:
                self._salt = None

        if self.username and self._salt:
            try:
                salt_path = os.path.join(self.data_dir, f"{self.username}.salt")
                with open(salt_path, "wb") as f:
                    f.write(self._salt)
            except Exception as e:
                print(f"[!] Erro ao guardar salt: {e}")

    # ==========================================
    # 1. CHAVES DE IDENTIDADE E ENCRIPTAÇÃO
    # ==========================================

    def load_or_generate_identity_keys(self, password_kdf: bytes, user: str) -> str:
        self.set_username(user)
        if not self.username:
            raise ValueError("Username não pode ser vazio")
        if not password_kdf:
            raise ValueError("password_kdf não pode ser vazio")

        # Ed25519 Identity Keys
        priv_path = os.path.join(self.data_dir, f"{user}_priv.pem")
        pub_path  = os.path.join(self.data_dir, f"{user}_pub.pem")
        cert_path = os.path.join(self.data_dir, f"{user}_cert.pem")

        # X25519 Encryption Keys
        enc_priv_path = os.path.join(self.data_dir, f"{user}_enc_priv.pem")
        enc_pub_path  = os.path.join(self.data_dir, f"{user}_enc_pub.pem")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            try:
                with open(priv_path, "rb") as f:
                    serialization.load_pem_private_key(f.read(), password=password_kdf)
                with open(pub_path, "rb") as f:
                    self.identity_pub_key = serialization.load_pem_public_key(f.read())
                print("[*] Chaves de identidade Ed25519 carregadas")
            except ValueError as e:
                if "Bad decrypt" in str(e):
                    print("[!] Password incorreta para chaves de identidade.")
                    return None
                else:
                    raise

        if not os.path.exists(priv_path):
            print("[*] A gerar novo par de chaves Ed25519...")
            if os.path.exists(cert_path): os.remove(cert_path)
            priv_key = ed25519.Ed25519PrivateKey.generate()
            self.identity_pub_key = priv_key.public_key()

            priv_pem = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password_kdf)
            )
            pub_pem = self.identity_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(priv_path, "wb") as f: f.write(priv_pem)
            with open(pub_path, "wb") as f: f.write(pub_pem)

        # Tratar chaves de encriptação X25519
        if os.path.exists(enc_priv_path):
            try:
                with open(enc_priv_path, "rb") as f:
                    self.encryption_priv_key = serialization.load_pem_private_key(f.read(), password=password_kdf)
                with open(enc_pub_path, "rb") as f:
                    self.encryption_pub_key = serialization.load_pem_public_key(f.read())
                print("[*] Chaves de encriptação X25519 carregadas")
            except Exception:
                print("[!] Falha ao carregar chaves X25519, a gerar novas...")
                if os.path.exists(enc_priv_path): os.remove(enc_priv_path)

        if not os.path.exists(enc_priv_path):
            print("[*] A gerar novo par de chaves X25519...")
            self.encryption_priv_key = x25519.X25519PrivateKey.generate()
            self.encryption_pub_key = self.encryption_priv_key.public_key()
            
            enc_priv_pem = self.encryption_priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password_kdf)
            )
            enc_pub_pem = self.encryption_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(enc_priv_path, "wb") as f: f.write(enc_priv_pem)
            with open(enc_pub_path, "wb") as f: f.write(enc_pub_pem)

        # Certificado
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                self.identity_cert = f.read()
        else:
            pub_pem = self.identity_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.identity_cert = self._generate_self_signed_cert(user, pub_pem, password_kdf)
            with open(cert_path, "wb") as f: f.write(self.identity_cert)

        pub_pem = self.identity_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pub_pem).decode("utf-8")

    def load_identity_keys(self, password_kdf: bytes, user: str) -> bool:
        """Lê chaves e certificado do disco se existirem."""
        self.set_username(user)
        priv_path = os.path.join(self.data_dir, f"{user}_priv.pem")
        pub_path  = os.path.join(self.data_dir, f"{user}_pub.pem")
        cert_path = os.path.join(self.data_dir, f"{user}_cert.pem")
        enc_priv_path = os.path.join(self.data_dir, f"{user}_enc_priv.pem")

        if not os.path.exists(priv_path) or not os.path.exists(pub_path):
            print(f"[DEBUG] Chaves de identidade não encontradas em {priv_path}")
            return False

        try:
            with open(pub_path, "rb") as f:
                self.identity_pub_key = serialization.load_pem_public_key(f.read())
            if os.path.exists(cert_path):
                with open(cert_path, "rb") as f:
                    self.identity_cert = f.read()
            
            # Tentar carregar X25519 se a password_kdf for fornecida
            if password_kdf and os.path.exists(enc_priv_path):
                with open(enc_priv_path, "rb") as f:
                    self.encryption_priv_key = serialization.load_pem_private_key(f.read(), password=password_kdf)
                
                import hashlib
                k_hash = hashlib.sha256(self.encryption_priv_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                )).hexdigest()[:8]
                print(f"[*] Chave de encriptação carregada (Hash: {k_hash})")

                enc_pub_path = os.path.join(self.data_dir, f"{user}_enc_pub.pem")
                if os.path.exists(enc_pub_path):
                    with open(enc_pub_path, "rb") as f:
                        self.encryption_pub_key = serialization.load_pem_public_key(f.read())
            else:
                print(f"[DEBUG] X25519 não carregada. iden_kdf={password_kdf is not None}, exists={os.path.exists(enc_priv_path)}")
            
            return True
        except Exception as e:
            print(f"[!] Erro ao carregar chaves de {user}: {e}")
            return False

    def rotate_encryption_key(self, password_kdf: bytes) -> bytes:
        """Gera um novo par de chaves X25519 e guarda no disco."""
        if not self.username:
            raise ValueError("Username não definido")
        
        print(f"[*] A rotacionar chave de encriptação X25519 para {self.username}...")
        
        enc_priv_path = os.path.join(self.data_dir, f"{self.username}_enc_priv.pem")
        enc_pub_path  = os.path.join(self.data_dir, f"{self.username}_enc_pub.pem")

        self.encryption_priv_key = x25519.X25519PrivateKey.generate()
        self.encryption_pub_key = self.encryption_priv_key.public_key()
        
        enc_priv_pem = self.encryption_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password_kdf)
        )
        enc_pub_pem = self.encryption_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(enc_priv_path, "wb") as f: f.write(enc_priv_pem)
        with open(enc_pub_path, "wb") as f: f.write(enc_pub_pem)
        
        return self.get_encryption_key_raw()

    def get_encryption_key_raw(self) -> bytes:
        if not self.encryption_pub_key:
            return None
        return self.encryption_pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def _generate_self_signed_cert(self, username: str, public_key_pem: bytes, password_kdf: bytes = None) -> bytes:
        public_key = serialization.load_pem_public_key(public_key_pem)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])

        priv_path = os.path.join(self.data_dir, f"{username}_priv.pem")
        with open(priv_path, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=password_kdf)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    key_cert_sign=False, crl_sign=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False
                ), critical=True
            )
            .sign(priv_key, algorithm=None)
        )

        cert_pem  = cert.public_bytes(serialization.Encoding.PEM)
        cert_path = os.path.join(self.data_dir, f"{username}_cert.pem")
        with open(cert_path, "wb") as f:
            f.write(cert_pem)

        self.identity_cert = cert_pem
        return cert_pem

    def get_certificate(self) -> str:
        if not self.identity_cert:
            raise ValueError("Certificate not generated.")
        return base64.b64encode(self.identity_cert).decode("utf-8")

    def get_public_key_pem(self) -> str:
        if not self.identity_pub_key:
            raise ValueError("Public key not loaded.")
        return self.identity_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def get_salt(self) -> bytes:
        local_salt_path = os.path.join(self.data_dir, f"{self.username}.salt")
        if os.path.exists(local_salt_path):
            with open(local_salt_path, "rb") as f:
                return f.read()
        return self._salt

    def sign_with_identity_key(self, data: bytes) -> bytes:
        """Carrega chave privada temporariamente, assina e descarta."""
        priv_path = os.path.join(self.data_dir, f"{self.username}_priv.pem")

        local_salt_path = os.path.join(self.data_dir, f"{self.username}.salt")
        if os.path.exists(local_salt_path):
            with open(local_salt_path, "rb") as f:
                local_salt = f.read()
        elif self._salt:
            local_salt = self._salt
        else:
            raise ValueError(f"Salt não encontrado para {self.username}")

        password_kdf = derive_key_PBKDF2HMAC(self._temp_password, local_salt)[0]

        with open(priv_path, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=password_kdf)

        return priv_key.sign(data)

    # ==========================================
    # 2. HANDSHAKE P2P (X25519 ECDH + Ed25519)
    # ==========================================

    def get_handshake_data(self, peer_username: str) -> dict:
        """
        Gera chave efémera X25519 e assina-a com Ed25519.
        Devolve dict com pub_key, signature e cert.
        """
        eph_priv_key = x25519.X25519PrivateKey.generate()
        eph_pub_raw  = eph_priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        self.pending_ephemeral_priv_keys[peer_username] = eph_priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        signature = self.sign_with_identity_key(eph_pub_raw)

        return {
            "pub_key":   base64.b64encode(eph_pub_raw).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "cert":      base64.b64encode(self.identity_cert).decode('utf-8') if self.identity_cert else None,
        }

    def verify_peer_handshake(self, peer_username: str, pub_key_b64: str,
                               signature_b64: str, cert_b64: str) -> bool:
        """
        Verifica a assinatura Ed25519 sobre a chave efémera X25519 do peer.
        Guarda o certificado em cache para uso posterior (ratchet, etc).
        """
        try:
            eph_pub_raw = base64.b64decode(pub_key_b64)
            signature   = base64.b64decode(signature_b64)
            cert_pem    = base64.b64decode(cert_b64)

            cert = x509.load_pem_x509_certificate(cert_pem)
            peer_identity_pub = cert.public_key()

            if not isinstance(peer_identity_pub, Ed25519PublicKey):
                print(f"[!] Certificado de {peer_username} não contém chave Ed25519")
                return False

            peer_identity_pub.verify(signature, eph_pub_raw)

            # Guardar certificado em cache local para o ratchet verificar depois
            cert_cache_path = os.path.join(self.data_dir, f"{peer_username}_cert.pem")
            with open(cert_cache_path, "wb") as f:
                f.write(cert_pem)

            print(f"[*] Assinatura do handshake de {peer_username} verificada")
            return True

        except InvalidSignature:
            print(f"[!!!] AVISO DE SEGURANÇA: Assinatura inválida no handshake de {peer_username}! Possível MITM.")
            return False
        except Exception as e:
            print(f"[!] Erro na verificação do handshake de {peer_username}: {e}")
            return False

    def process_peer_handshake(self, peer_username: str, peer_pub_key_b64: str):
        """Deriva a chave de sessão ECDH após verificação da assinatura."""
        try:
            peer_pub_raw    = base64.b64decode(peer_pub_key_b64)
            my_eph_priv_raw = self.pending_ephemeral_priv_keys.pop(peer_username, None)

            if not my_eph_priv_raw:
                print(f"[Erro] Chave efémera não encontrada para {peer_username}")
                return

            my_priv_key   = x25519.X25519PrivateKey.from_private_bytes(my_eph_priv_raw)
            peer_pub_key  = x25519.X25519PublicKey.from_public_bytes(peer_pub_raw)
            shared_secret = my_priv_key.exchange(peer_pub_key)
            
            # HKDF: Derivar chave de 32 bytes
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"P2PChat",
            )
            session_key = hkdf.derive(shared_secret)

            self.active_sessions[peer_username]  = session_key
            self.peer_public_keys[peer_username] = peer_pub_raw

            print(f"[*] Sessão X25519 estabelecida com {peer_username}")

        except Exception as e:
            print(f"[Erro] Handshake X25519 falhou: {e}")

    # ==========================================
    # 3. RATCHET COM SALT CONTRIBUÍDO PELOS CLIENTES
    # ==========================================

    def generate_ratchet_contribution(self, peer_username: str) -> dict:
        """
        Gera novo salt contribution (16 bytes) e assina com a chave de identidade.
        Guarda localmente em pending_ratchet_salt.
        """
        my_salt = os.urandom(16)
        self.pending_ratchet_salt[peer_username] = my_salt

        signature = self.sign_with_identity_key(my_salt)

        return {
            "salt_contribution": base64.b64encode(my_salt).decode('utf-8'),
            "signature":         base64.b64encode(signature).decode('utf-8'),
        }

    def verify_and_apply_ratchet(self, peer_username: str,
                                  peer_salt_b64: str, peer_sig_b64: str) -> Tuple[Optional[bytes], Optional[dict]]:
        """
        Recebe a contribuição de salt do peer e verifica a assinatura.
        Devolve (nova_chave, reply_contribution).
        """
        if peer_username not in self.active_sessions:
            print(f"[Erro] Não há sessão ativa com {peer_username}")
            return None, None

        # Verificar se fomos nós a iniciar
        my_salt = self.pending_ratchet_salt.pop(peer_username, None)
        reply_contribution = None

        if not my_salt:
            # Recetor: gera seu salt agora
            my_salt = os.urandom(16)
            signature = self.sign_with_identity_key(my_salt)
            reply_contribution = {
                "salt_contribution": base64.b64encode(my_salt).decode('utf-8'),
                "signature":         base64.b64encode(signature).decode('utf-8'),
            }

        try:
            peer_salt = base64.b64decode(peer_salt_b64)
            peer_sig  = base64.b64decode(peer_sig_b64)

            cert_cache_path = os.path.join(self.data_dir, f"{peer_username}_cert.pem")
            with open(cert_cache_path, "rb") as f:
                peer_cert = x509.load_pem_x509_certificate(f.read())

            peer_pub = peer_cert.public_key()
            peer_pub.verify(peer_sig, peer_salt)

        except Exception as e:
            print(f"[!!!] Erro de segurança no ratchet de {peer_username}: {e}")
            return None, None

        # Derivação determinística
        names = sorted([self.username, peer_username])
        combined = my_salt + peer_salt if names[0] == self.username else peer_salt + my_salt

        digest = hashes.Hash(hashes.SHA256())
        digest.update(combined)
        final_salt = digest.finalize()

        current_key = self.active_sessions[peer_username]
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=final_salt,
            info=b"P2PChatRatchet",
        )
        new_key = hkdf.derive(current_key)
        
        # O cliente é que vai chamar self.active_sessions[peer] = new_key
        return new_key, reply_contribution

    # ==========================================
    # 4. ENCRIPTAÇÃO DE MENSAGENS (AES-GCM)
    # ==========================================

    def encrypt_for_peer(self, peer_username: str, plaintext: str) -> Optional[Dict[str, str]]:
        if peer_username not in self.active_sessions:
            print(f"[Erro] Não há sessão segura com {peer_username}")
            return None

        from crypto import symmetric
        session_key     = self.active_sessions[peer_username]
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext, nonce, tag = symmetric.encrypt(session_key, plaintext_bytes)

        return {
            "content": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce":   base64.b64encode(nonce).decode('utf-8'),
            "tag":     base64.b64encode(tag).decode('utf-8')
        }

    def decrypt_from_peer(self, peer_username: str, payload: dict) -> Optional[str]:
        if peer_username not in self.active_sessions:
            print(f"[Erro] Não há sessão com {peer_username}")
            return None

        try:
            from crypto import symmetric
            session_key = self.active_sessions[peer_username]
            ciphertext  = base64.b64decode(payload["content"])
            nonce       = base64.b64decode(payload["nonce"])
            tag         = base64.b64decode(payload["tag"])

            return symmetric.decrypt(session_key, ciphertext, nonce, tag).decode('utf-8')

        except Exception as e:
            print(f"[Erro] Desencriptação falhou: {e}")
            return None

    # ==========================================
    # 5. MENSAGENS OFFLINE (SECURE - EPHEMERAL-STATIC ECDH)
    # ==========================================

    def encrypt_offline(self, recipient_enc_key_b64: str, plaintext: str) -> dict:
        """
        Alice encripta mensagem para Bob (offline) usando a chave estática X25519 de Bob.
        Gera uma chave efémera X25519 para Alice e deriva segredo via ECDH.
        """
        try:
            recipient_pub_raw = base64.b64decode(recipient_enc_key_b64)
            recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_pub_raw)

            # Alice gera efémera
            my_eph_priv = x25519.X25519PrivateKey.generate()
            my_eph_pub  = my_eph_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # Derivar chave
            shared_secret = my_eph_priv.exchange(recipient_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"OfflineSecureMessage"
            )
            session_key = hkdf.derive(shared_secret)

            # Encriptar
            from crypto import symmetric
            ciphertext, nonce, tag = symmetric.encrypt(session_key, plaintext.encode('utf-8'))

            return {
                "content":       base64.b64encode(ciphertext).decode('utf-8'),
                "nonce":         base64.b64encode(nonce).decode('utf-8'),
                "tag":           base64.b64encode(tag).decode('utf-8'),
                "ephemeral_key": base64.b64encode(my_eph_pub).decode('utf-8')
            }
        except Exception as e:
            print(f"[Erro] Encriptação offline segura falhou: {e}")
            return None

    def decrypt_offline(self, m: dict) -> str:
        """
        Bob desencripta mensagem offline usando a sua chave estática X25519
        e a chave efémera da Alice contida no payload.
        """
        try:
            if not self.encryption_priv_key:
                return "(Erro: Chave de encriptação não carregada)"

            eph_pub_raw = base64.b64decode(m["ephemeral_key"])
            eph_pub     = x25519.X25519PublicKey.from_public_bytes(eph_pub_raw)

            # Bob usa a sua chave privada estática
            import hashlib
            my_pub_hash = hashlib.sha256(self.encryption_priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )).hexdigest()[:8]
            print(f"[*] A desencriptar com a minha chave privada (PubHash: {my_pub_hash})")

            shared_secret = self.encryption_priv_key.exchange(eph_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"OfflineSecureMessage"
            )
            session_key = hkdf.derive(shared_secret)

            # Desencriptar
            from crypto import symmetric
            ciphertext = base64.b64decode(m["content"])
            nonce      = base64.b64decode(m["nonce"])
            tag        = base64.b64decode(m["tag"])

            return symmetric.decrypt(session_key, ciphertext, nonce, tag).decode('utf-8')

        except Exception as e:
            print(f"[!!!] Erro na desencriptação offline: {type(e).__name__}: {e}")
            return "(Erro ao desencriptar mensagem offline)"
