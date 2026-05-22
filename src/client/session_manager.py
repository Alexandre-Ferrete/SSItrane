import os
import json
import base64
import utils.helpers as help
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
from crypto import generate_keypair_Ed25519
from crypto.kdf import derive_key_PBKDF2HMAC
from crypto import generate_keypair as generate_x25519_keypair
from crypto import perform_exchange, derive_key as derive_key_from_ecdh
from crypto.symmetric import generate_key as generate_symmetric_key, encrypt, decrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID


class SessionManager:

    def __init__(self, username: str = None, data_dir: str = "client_data"):
        self.username = username
        self.data_dir = data_dir

        self.identity_pub_key: Optional[object] = None
        self.identity_cert: Optional[bytes] = None

        self._temp_password: Optional[str] = None
        self._salt: Optional[bytes] = None

        self.pending_ephemeral_priv_keys: Dict[str, bytes] = {}
        self.pending_ephemeral_pub_keys: Dict[str, str] = {}
        self.peer_public_keys: Dict[str, bytes] = {}
        self.active_sessions: Dict[str, bytes] = {}

        # Ratchet: guarda a contribuição local de salt até receber a do peer
        self.pending_ratchet_salt: Dict[str, bytes] = {}

        if username:
            self._ensure_dir()

    def set_password(self, password: str):
        self._temp_password = password

    def clear_password(self):
        self._temp_password = None

    def set_username(self, username: str):
        self.username = username
        self._ensure_dir()
        print(f"[*] SessionManager configurado para: {username}")

    def set_salt(self, salt):
        self.salt = salt
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

    def _ensure_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    # ==========================================
    # 1. CHAVES DE IDENTIDADE
    # ==========================================

    def load_or_generate_identity_keys(self, password_kdf: bytes, user: str) -> str:
        self.set_username(user)
        if not self.username:
            raise ValueError("Username não pode ser vazio")
        if not password_kdf:
            raise ValueError("password_kdf não pode ser vazio")

        priv_path = os.path.join(self.data_dir, f"{user}_priv.pem")
        pub_path  = os.path.join(self.data_dir, f"{user}_pub.pem")
        cert_path = os.path.join(self.data_dir, f"{user}_cert.pem")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            try:
                with open(priv_path, "rb") as f:
                    serialization.load_pem_private_key(f.read(), password=password_kdf)
                with open(pub_path, "rb") as f:
                    self.identity_pub_key = serialization.load_pem_public_key(f.read())
                print("[*] Chaves carregadas do disco")
            except ValueError as e:
                if "Bad decrypt" in str(e):
                    print("[!] Password incorreta. A gerar novas chaves...")
                    for fp in [priv_path, pub_path, cert_path]:
                        if os.path.exists(fp):
                            os.remove(fp)
                else:
                    raise

        if not os.path.exists(priv_path):
            print("[*] A gerar novo par de chaves Ed25519...")
            priv_key, pub_key = generate_keypair_Ed25519()
            self.identity_pub_key = pub_key

            priv_pem = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password_kdf)
            )
            pub_pem = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(priv_path, "wb") as f:
                f.write(priv_pem)
            with open(pub_path, "wb") as f:
                f.write(pub_pem)

        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                self.identity_cert = f.read()
        else:
            pub_pem = self.identity_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.identity_cert = self._generate_self_signed_cert(user, pub_pem, password_kdf)
            with open(cert_path, "wb") as f:
                f.write(self.identity_cert)

        pub_pem = self.identity_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pub_pem).decode("utf-8")

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
        eph_priv_pem, eph_pub_raw = generate_x25519_keypair()
        self.pending_ephemeral_priv_keys[peer_username] = eph_priv_pem

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
            my_eph_priv_pem = self.pending_ephemeral_priv_keys.pop(peer_username, None)

            if not my_eph_priv_pem:
                print(f"[Erro] Chave efémera não encontrada para {peer_username}")
                return

            shared_secret = perform_exchange(my_eph_priv_pem, peer_pub_raw)
            session_key   = derive_key_from_ecdh(shared_secret, length=32, info=b"P2PChat")

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
        Gera 16 bytes aleatórios como contribuição local para o ratchet.
        Assina-os com Ed25519 para o peer poder verificar autenticidade.

        O servidor nunca vê este valor — é enviado diretamente pelo
        canal P2P já cifrado com AES-GCM.

        Retorna dict com:
            salt_contribution : bytes aleatórios em base64
            signature         : Ed25519(salt_contribution) em base64
        """
        my_salt = os.urandom(16)
        # Guardar para combinar quando chegar a contribuição do peer
        self.pending_ratchet_salt[peer_username] = my_salt

        signature = self.sign_with_identity_key(my_salt)

        return {
            "salt_contribution": base64.b64encode(my_salt).decode('utf-8'),
            "signature":         base64.b64encode(signature).decode('utf-8'),
        }

    def verify_and_apply_ratchet(self, peer_username: str,
                                  peer_salt_b64: str, peer_sig_b64: str) -> bool:
        """
        Recebe a contribuição de salt do peer, verifica a assinatura Ed25519
        e aplica o ratchet com o salt combinado.

        Salt final = SHA-256( sort(meu_salt, salt_peer) )

        A ordenação por username garante que ambos os lados chegam ao mesmo
        salt combinado de forma determinista, sem comunicação extra.

        O servidor não intervém — o ratchet é completamente P2P.

        Retorna True se aplicado com sucesso.
        """
        if peer_username not in self.active_sessions:
            print(f"[Erro] Não há sessão com {peer_username}")
            return False

        my_salt = self.pending_ratchet_salt.pop(peer_username, None)
        if not my_salt:
            print(f"[Erro] Contribuição local de salt não encontrada para {peer_username}")
            return False

        try:
            peer_salt = base64.b64decode(peer_salt_b64)
            peer_sig  = base64.b64decode(peer_sig_b64)

            # Carregar certificado do peer em cache (guardado no handshake)
            cert_cache_path = os.path.join(self.data_dir, f"{peer_username}_cert.pem")
            if not os.path.exists(cert_cache_path):
                print(f"[Erro] Certificado de {peer_username} não encontrado em cache")
                return False

            with open(cert_cache_path, "rb") as f:
                peer_cert = x509.load_pem_x509_certificate(f.read())

            peer_pub = peer_cert.public_key()
            if not isinstance(peer_pub, Ed25519PublicKey):
                print(f"[Erro] Chave do peer não é Ed25519")
                return False

            # Verificar assinatura Ed25519 do peer sobre o seu salt
            # Lança InvalidSignature se inválida
            peer_pub.verify(peer_sig, peer_salt)

        except InvalidSignature:
            print(f"[!!!] AVISO DE SEGURANÇA: Salt de ratchet de {peer_username} com assinatura inválida!")
            return False
        except Exception as e:
            print(f"[Erro] Verificação do ratchet falhou: {e}")
            return False

        # Ordenar por username para determinismo — ambos os lados chegam à
        # mesma concatenação sem coordenação extra
        names = sorted([self.username, peer_username])
        if names[0] == self.username:
            combined = my_salt + peer_salt
        else:
            combined = peer_salt + my_salt

        # SHA-256 do salt combinado: nenhum lado controla sozinho o resultado
        digest = hashes.Hash(hashes.SHA256())
        digest.update(combined)
        final_salt = digest.finalize()

        # HKDF: nova chave de sessão a partir da chave atual + salt combinado
        current_key = self.active_sessions[peer_username]
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=final_salt,
            info=b"P2PChatRatchet",
        )
        self.active_sessions[peer_username] = hkdf.derive(current_key)
        print(f"[*] Ratchet aplicado para {peer_username} (salt P2P, sem intervenção do servidor)")
        return True

    # ==========================================
    # 4. ENCRIPTAÇÃO DE MENSAGENS (AES-GCM)
    # ==========================================

    def encrypt_for_peer(self, peer_username: str, plaintext: str) -> Optional[Dict[str, str]]:
        if peer_username not in self.active_sessions:
            print(f"[Erro] Não há sessão segura com {peer_username}")
            return None

        session_key     = self.active_sessions[peer_username]
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext, nonce, tag = encrypt(session_key, plaintext_bytes)

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
            session_key = self.active_sessions[peer_username]
            ciphertext  = base64.b64decode(payload["content"])
            nonce       = base64.b64decode(payload["nonce"])
            tag         = base64.b64decode(payload["tag"])

            return decrypt(session_key, ciphertext, nonce, tag).decode('utf-8')

        except Exception as e:
            print(f"[Erro] Desencriptação falhou: {e}")
            return None

    def encrypt_offline(self, recipient_pub_key_b64: str, text: str) -> Dict[str, str]:
        from crypto.hybrid import encrypt_content
        try:
            return encrypt_content(text, recipient_pub_key_b64)
        except Exception as e:
            print(f"[Erro] Encriptação offline falhou: {e}")
            ciphertext = f"OFFLINE_ENC({text})".encode('utf-8')
            return {
                "content": help.encode_base64(ciphertext),
                "nonce":   help.encode_base64(b"static_nonce"),
                "tag":     help.encode_base64(b"static_tag")
            }

    def decrypt_offline(self, encrypted_payload: dict) -> str:
        from crypto.hybrid import decrypt_content
        try:
            return decrypt_content(encrypted_payload)
        except Exception as e:
            print(f"[Erro] Desencriptação offline falhou: {e}")
            content_b64 = encrypted_payload.get("content")
            raw_bytes   = help.decode_base64(content_b64)
            return raw_bytes.decode('utf-8').replace("OFFLINE_ENC(", "").replace(")", "")