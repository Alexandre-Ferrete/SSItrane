import os
import json
import base64
import hashlib
import math
import traceback
from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID

from crypto import symmetric

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
        print("[DEBUG] SessionManager v12 (P2P Stability) carregado.")
        self.username = username
        self.data_dir = data_dir
        self._ensure_dir()

        self.identity_priv_key: Optional[Ed25519PrivateKey] = None
        self.identity_pub_key:  Optional[Ed25519PublicKey]  = None
        self.identity_cert:     Optional[bytes] = None

        self.encryption_priv_key: Optional[x25519.X25519PrivateKey] = None
        self.encryption_pub_key:  Optional[x25519.X25519PublicKey]  = None

        self.active_sessions: Dict[str, bytes] = {}
        self.group_states:    Dict[str, Dict[str, Any]] = {}
        
        self.pending_ephemeral_priv_keys: Dict[str, bytes] = {}
        self.pending_ratchet_salt:         Dict[str, bytes] = {}

        self._salt = None
        self._temp_password = None

    def _ensure_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def set_username(self, username: str):
        self.username = username
        self._ensure_dir()

    def set_password(self, password: str):
        self._temp_password = password

    def set_salt(self, salt):
        if isinstance(salt, bytes): self._salt = salt
        else:
            try: self._salt = base64.b64decode(salt)
            except: self._salt = None
        if self.username and self._salt:
            try:
                with open(os.path.join(self.data_dir, f"{self.username}.salt"), "wb") as f: f.write(self._salt)
            except: pass

    # ==========================================
    # 1. GESTÃO DE CHAVES
    # ==========================================

    def load_or_generate_identity_keys(self, password_kdf: bytes, user: str) -> str:
        self.set_username(user)
        priv_path = os.path.join(self.data_dir, f"{user}_priv.pem")
        if os.path.exists(priv_path):
            if self.load_identity_keys(password_kdf, user):
                return self.get_public_key_pem()

        print(f"[*] A gerar novas chaves para {user}...")
        try:
            self.identity_priv_key = ed25519.Ed25519PrivateKey.generate()
            self.identity_pub_key  = self.identity_priv_key.public_key()
            self.encryption_priv_key = x25519.X25519PrivateKey.generate()
            self.encryption_pub_key  = self.encryption_priv_key.public_key()
            self._save_keys_to_disk(password_kdf, user)
            pub_pem = self.get_public_key_pem().encode('utf-8')
            self.identity_cert = self._generate_self_signed_cert(user, pub_pem, password_kdf)
            return self.get_public_key_pem()
        except Exception:
            traceback.print_exc()
            return ""

    def load_identity_keys(self, password_kdf: bytes, user: str) -> bool:
        self.set_username(user)
        priv_path = os.path.join(self.data_dir, f"{user}_priv.pem")
        enc_priv_path = os.path.join(self.data_dir, f"{user}_enc_priv.pem")
        if not os.path.exists(priv_path) or not os.path.exists(enc_priv_path): return False
        try:
            with open(priv_path, "rb") as f:
                self.identity_priv_key = serialization.load_pem_private_key(f.read(), password=password_kdf)
            self.identity_pub_key = self.identity_priv_key.public_key()
            with open(enc_priv_path, "rb") as f:
                self.encryption_priv_key = serialization.load_pem_private_key(f.read(), password=password_kdf)
            self.encryption_pub_key = self.encryption_priv_key.public_key()
            cert_path = os.path.join(self.data_dir, f"{user}_cert.pem")
            if os.path.exists(cert_path):
                with open(cert_path, "rb") as f: self.identity_cert = f.read()
            self._load_group_states(password_kdf)
            return True
        except Exception as e:
            print(f"[!] Falha ao desencriptar chaves de {user}: {e}")
            return False

    def _save_keys_to_disk(self, password_kdf: bytes, user: str):
        paths = {
            f"{user}_priv.pem": (self.identity_priv_key, serialization.PrivateFormat.PKCS8),
            f"{user}_pub.pem":  (self.identity_pub_key, serialization.PublicFormat.SubjectPublicKeyInfo),
            f"{user}_enc_priv.pem": (self.encryption_priv_key, serialization.PrivateFormat.PKCS8),
            f"{user}_enc_pub.pem":  (self.encryption_pub_key, serialization.PublicFormat.SubjectPublicKeyInfo)
        }
        for name, (key, fmt) in paths.items():
            if key is None: continue
            path = os.path.join(self.data_dir, name)
            with open(path, "wb") as f:
                if isinstance(fmt, serialization.PrivateFormat):
                    f.write(key.private_bytes(serialization.Encoding.PEM, fmt, serialization.BestAvailableEncryption(password_kdf)))
                else:
                    f.write(key.public_bytes(serialization.Encoding.PEM, fmt))

    def _save_group_states(self, password_kdf: bytes):
        if not self.username or not password_kdf: return
        try:
            serializable = {}
            for room, state in self.group_states.items():
                serializable[room] = {
                    "epoch": state["epoch"], "my_leaf_index": state["my_leaf_index"], "total_leaves": state["total_leaves"],
                    "group_key": base64.b64encode(state["group_key"]).decode('utf-8'),
                    "tree_priv_keys": {str(k): base64.b64encode(v).decode('utf-8') for k,v in state["tree_priv_keys"].items()},
                    "tree_pub_keys": {str(k): base64.b64encode(v).decode('utf-8') for k,v in state["tree_pub_keys"].items()},
                    "members_cache": state.get("members_cache", [])
                }
            c, n, t = symmetric.encrypt(password_kdf, json.dumps(serializable).encode('utf-8'))
            with open(os.path.join(self.data_dir, f"{self.username}_groups.json.enc"), "wb") as f: f.write(n + t + c)
        except: pass

    def _load_group_states(self, password_kdf: bytes):
        path = os.path.join(self.data_dir, f"{self.username}_groups.json.enc")
        if not os.path.exists(path): return
        try:
            with open(path, "rb") as f:
                raw = f.read()
                if len(raw) < 28: return
                n, t, c = raw[:12], raw[12:28], raw[28:]
            plaintext = symmetric.decrypt(password_kdf, c, n, t)
            data = json.loads(plaintext.decode('utf-8'))
            for room, s in data.items():
                self.group_states[room] = {
                    "epoch": s["epoch"], "my_leaf_index": s["my_leaf_index"], "total_leaves": s["total_leaves"],
                    "group_key": base64.b64decode(s["group_key"]),
                    "tree_priv_keys": {int(k): base64.b64decode(v) for k,v in s["tree_priv_keys"].items()},
                    "tree_pub_keys": {int(k): base64.b64decode(v) for k,v in s["tree_pub_keys"].items()},
                    "members_cache": s.get("members_cache", [])
                }
        except: pass

    def rotate_encryption_key(self, password_kdf: bytes) -> bytes:
        if not self.username: raise ValueError("Username não definido")
        self.encryption_priv_key = x25519.X25519PrivateKey.generate()
        self.encryption_pub_key = self.encryption_priv_key.public_key()
        self._save_keys_to_disk(password_kdf, self.username)
        return self.get_encryption_key_raw()

    def get_encryption_key_raw(self) -> bytes:
        return self.encryption_pub_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) if self.encryption_pub_key else None

    def _generate_self_signed_cert(self, username: str, public_key_pem: bytes, password_kdf: bytes) -> bytes:
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(self.identity_pub_key)
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.identity_priv_key, algorithm=None))
        self.identity_cert = cert.public_bytes(serialization.Encoding.PEM)
        with open(os.path.join(self.data_dir, f"{username}_cert.pem"), "wb") as f: f.write(self.identity_cert)
        return self.identity_cert

    def get_certificate(self) -> str:
        return base64.b64encode(self.identity_cert).decode("utf-8") if self.identity_cert else ""

    def get_public_key_pem(self) -> str:
        return self.identity_pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8") if self.identity_pub_key else ""

    def get_salt(self) -> bytes:
        if self._salt: return self._salt
        try:
            with open(os.path.join(self.data_dir, f"{self.username}.salt"), "rb") as f: return f.read()
        except: return None

    def sign_with_identity_key(self, data: bytes) -> bytes:
        if not self.identity_priv_key: raise ValueError("Chave de identidade não carregada")
        return self.identity_priv_key.sign(data)

    # ==========================================
    # 2. HANDSHAKE P2P & RATCHET
    # ==========================================

    def get_handshake_data(self, peer: str) -> dict:
        try:
            eph = x25519.X25519PrivateKey.generate()
            self.pending_ephemeral_priv_keys[peer] = eph.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return {"pub_key": base64.b64encode(pub).decode('utf-8'), "signature": base64.b64encode(self.sign_with_identity_key(pub)).decode('utf-8'), "cert": self.get_certificate()}
        except Exception:
            traceback.print_exc()
            return {}

    def verify_peer_handshake(self, peer: str, pub_b64: str, sig_b64: str, cert_b64: str) -> bool:
        if not pub_b64 or not sig_b64 or not cert_b64: return False
        try:
            pub, sig, cert_pem = base64.b64decode(pub_b64), base64.b64decode(sig_b64), base64.b64decode(cert_b64)
            cert = x509.load_pem_x509_certificate(cert_pem)
            # Verify cert was signed by the server CA
            ca_pub_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ca_public.key")
            with open(ca_pub_path, "rb") as f:
                ca_pub_key = serialization.load_pem_public_key(f.read())
            ca_pub_key.verify(cert.signature, cert.tbs_certificate_bytes)
            # Verify the ephemeral pub key was signed with the peer's identity key
            cert.public_key().verify(sig, pub)
            with open(os.path.join(self.data_dir, f"{peer}_cert.pem"), "wb") as f: f.write(cert_pem)
            return True
        except: return False

    def process_peer_handshake(self, peer: str, pub_b64: str):
        try:
            raw = self.pending_ephemeral_priv_keys.pop(peer, None)
            if not raw: return
            shared = x25519.X25519PrivateKey.from_private_bytes(raw).exchange(x25519.X25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)))
            self.active_sessions[peer] = HKDF(hashes.SHA256(), 32, None, b"P2PChat").derive(shared)
        except: traceback.print_exc()

    def generate_ratchet_contribution(self, peer: str) -> dict:
        try:
            my_salt = os.urandom(16)
            self.pending_ratchet_salt[peer] = my_salt
            return {"salt_contribution": base64.b64encode(my_salt).decode('utf-8'), "signature": base64.b64encode(self.sign_with_identity_key(my_salt)).decode('utf-8')}
        except: return {}

    def verify_and_apply_ratchet(self, peer: str, ps: str, psig: str) -> Tuple[Optional[bytes], Optional[dict]]:
        if peer not in self.active_sessions: return None, None
        my_salt, reply = self.pending_ratchet_salt.pop(peer, None), None
        if not my_salt:
            my_salt = os.urandom(16)
            reply = {"salt_contribution": base64.b64encode(my_salt).decode('utf-8'), "signature": base64.b64encode(self.sign_with_identity_key(my_salt)).decode('utf-8')}
        try:
            ps_b, psig_b = base64.b64decode(ps), base64.b64decode(psig)
            with open(os.path.join(self.data_dir, f"{peer}_cert.pem"), "rb") as f:
                x509.load_pem_x509_certificate(f.read()).public_key().verify(psig_b, ps_b)
            u_names = sorted([self.username or "anon", peer])
            combined = my_salt + ps_b if u_names[0] == (self.username or "anon") else ps_b + my_salt
            new_key = HKDF(hashes.SHA256(), 32, hashlib.sha256(combined).digest(), b"P2PChatRatchet").derive(self.active_sessions[peer])
            return new_key, reply
        except: return None, None

    # ==========================================
    # 3. ENCRIPTAÇÃO
    # ==========================================

    def encrypt_for_peer(self, peer: str, text: str) -> Optional[dict]:
        if peer not in self.active_sessions: return None
        try:
            c, n, t = symmetric.encrypt(self.active_sessions[peer], text.encode('utf-8'))
            return {"content": base64.b64encode(c).decode('utf-8'), "nonce": base64.b64encode(n).decode('utf-8'), "tag": base64.b64encode(t).decode('utf-8')}
        except: return None

    def decrypt_from_peer(self, peer: str, payload: dict) -> Optional[str]:
        if peer not in self.active_sessions: return None
        try:
            return symmetric.decrypt(self.active_sessions[peer], base64.b64decode(payload["content"]), base64.b64decode(payload["nonce"]), base64.b64decode(payload["tag"])).decode('utf-8')
        except: return None

    def encrypt_offline(self, pub_b64: str, text: str) -> dict:
        try:
            my_eph = x25519.X25519PrivateKey.generate()
            shared = my_eph.exchange(x25519.X25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)))
            key = HKDF(hashes.SHA256(), 32, None, b"OfflineSecureMessage").derive(shared)
            c, n, t = symmetric.encrypt(key, text.encode('utf-8'))
            return {"content": base64.b64encode(c).decode('utf-8'), "nonce": base64.b64encode(n).decode('utf-8'), "tag": base64.b64encode(t).decode('utf-8'), "ephemeral_key": base64.b64encode(my_eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode('utf-8')}
        except: return {}

    def decrypt_offline(self, m: dict) -> str:
        try:
            if not self.encryption_priv_key: return "(Erro: Chave não carregada)"
            shared = self.encryption_priv_key.exchange(x25519.X25519PublicKey.from_public_bytes(base64.b64decode(m["ephemeral_key"])))
            key = HKDF(hashes.SHA256(), 32, None, b"OfflineSecureMessage").derive(shared)
            return symmetric.decrypt(key, base64.b64decode(m["content"]), base64.b64decode(m["nonce"]), base64.b64decode(m["tag"])).decode('utf-8')
        except: return "(Erro ao desencriptar)"

    # ==========================================
    # 4. TREEKEM
    # ==========================================

    def _get_path(self, idx: int) -> List[int]:
        path = []
        while idx > 1:
            idx //= 2
            path.append(idx)
        return path

    def derive_group_key(self, root_secret: bytes, epoch: int) -> bytes:
        return HKDF(hashes.SHA256(), 32, epoch.to_bytes(4, 'big'), b"GroupKey").derive(root_secret)

    def initialize_tree_as_creator(self, room: str, members: List[Dict[str, str]], password_kdf: bytes) -> dict:
        try:
            n = len(members)
            if n == 0: return {}
            depth = math.ceil(math.log2(n))
            total_leaves = 2**depth
            tree_pub, tree_priv = {}, {}
            my_idx = 0
            for i, m in enumerate(members):
                idx = total_leaves + i
                pub_raw = base64.b64decode(m['enc_pub_key'])
                tree_pub[idx] = pub_raw
                if m['username'] == self.username:
                    my_idx = idx
                    tree_priv[idx] = self.encryption_priv_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

            curr = my_idx
            while curr > 1:
                parent = curr // 2
                priv = x25519.X25519PrivateKey.generate()
                tree_priv[parent] = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                tree_pub[parent] = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                curr = parent

            pkgs = []
            for i, m in enumerate(members):
                if m['username'] == self.username: continue
                idx = total_leaves + i
                secrets = {str(k): base64.b64encode(v).decode('utf-8') for k,v in tree_priv.items() if k in self._get_path(idx)}
                blob = self.encrypt_group_key_for_member(json.dumps({"leaf_index": idx, "total_leaves": total_leaves, "path_secrets": secrets}).encode('utf-8'), m['enc_pub_key'])
                pkgs.append({"username": m['username'], "encrypted_blob": blob})

            self.group_states[room] = {"epoch": 0, "my_leaf_index": my_idx, "tree_priv_keys": tree_priv, "tree_pub_keys": tree_pub, "total_leaves": total_leaves, "group_key": self.derive_group_key(tree_priv[1], 0), "members_cache": [m['username'] for m in members]}
            self._save_group_states(password_kdf)
            return {"room_name": room, "total_leaves": total_leaves, "public_tree": {str(k): base64.b64encode(v).decode('utf-8') for k,v in tree_pub.items()}, "key_packages": pkgs}
        except Exception:
            traceback.print_exc()
            return {}

    def encrypt_group_key_for_member(self, data: bytes, pub_b64: str) -> dict:
        try:
            pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
            eph = x25519.X25519PrivateKey.generate()
            key = HKDF(hashes.SHA256(), 32, None, b"GroupKeyDistribution").derive(eph.exchange(pub))
            c, n, t = symmetric.encrypt(key, data)
            return {"content": base64.b64encode(c).decode('utf-8'), "nonce": base64.b64encode(n).decode('utf-8'), "tag": base64.b64encode(t).decode('utf-8'), "ephemeral_key": base64.b64encode(eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode('utf-8')}
        except: return {}

    def process_key_package(self, room: str, epoch: int, blob: dict, password_kdf: bytes) -> bool:
        if room in self.group_states and self.group_states[room]["epoch"] >= epoch: return True
        try:
            eph_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(blob["ephemeral_key"]))
            key = HKDF(hashes.SHA256(), 32, None, b"GroupKeyDistribution").derive(self.encryption_priv_key.exchange(eph_pub))
            plaintext = symmetric.decrypt(key, base64.b64decode(blob["content"]), base64.b64decode(blob["nonce"]), base64.b64decode(blob["tag"]))
            data = json.loads(plaintext.decode('utf-8'))
            t_priv = {int(k): base64.b64decode(v) for k,v in data["path_secrets"].items()}
            my_idx = data["leaf_index"]
            t_priv[my_idx] = self.encryption_priv_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            self.group_states[room] = {"epoch": epoch, "my_leaf_index": my_idx, "tree_priv_keys": t_priv, "tree_pub_keys": {}, "total_leaves": data["total_leaves"], "group_key": self.derive_group_key(t_priv[1], epoch)}
            self._save_group_states(password_kdf)
            return True
        except: return False

    def encrypt_for_group(self, room: str, text: str) -> Optional[dict]:
        if room not in self.group_states: return None
        try:
            c, n, t = symmetric.encrypt(self.group_states[room]["group_key"], text.encode('utf-8'))
            return {"room_name": room, "epoch": self.group_states[room]["epoch"], "content": base64.b64encode(c).decode('utf-8'), "nonce": base64.b64encode(n).decode('utf-8'), "tag": base64.b64encode(t).decode('utf-8')}
        except: return None

    def decrypt_from_group(self, room: str, epoch: int, payload: dict) -> Optional[str]:
        if room not in self.group_states: return None
        state = self.group_states[room]
        if epoch != state["epoch"]: return f"(Epoch mismatch: {epoch} != {state['epoch']})"
        try:
            return symmetric.decrypt(state["group_key"], base64.b64decode(payload["content"]), base64.b64decode(payload["nonce"]), base64.b64decode(payload["tag"])).decode('utf-8')
        except Exception as e: return f"(Erro de decifração: {e})"

    def add_member_to_tree(self, room: str, new_user: str, new_user_enc_pub_b64: str, password_kdf: bytes) -> dict:
        if room not in self.group_states: return {}
        try:
            state = self.group_states[room]
            members = state.get("members_cache", [self.username])
            if new_user in members: return {}

            new_leaf_idx = state["total_leaves"] + len(members)
            if new_leaf_idx >= state["total_leaves"] * 2:
                state["total_leaves"] *= 2

            state["tree_pub_keys"][new_leaf_idx] = base64.b64decode(new_user_enc_pub_b64)
            my_idx = state["my_leaf_index"]

            # Regenerar caminho do admin
            path_secrets = {}  # {node_idx: secret_bytes}
            curr_idx = my_idx
            for parent in self._get_path(my_idx):
                new_priv = x25519.X25519PrivateKey.generate()
                priv_raw = new_priv.private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
                )
                state["tree_priv_keys"][parent] = priv_raw
                state["tree_pub_keys"][parent] = new_priv.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                path_secrets[parent] = priv_raw
                curr_idx = parent

            state["epoch"] += 1
            state["group_key"] = self.derive_group_key(state["tree_priv_keys"][1], state["epoch"])
            members.append(new_user)
            state["members_cache"] = members
            self._save_group_states(password_kdf)

            # Novo: para cada membro existente, cifrar o segredo do nó
            # mais baixo do seu caminho que foi regenerado
            member_key_packages = []
            for member_username in members:
                if member_username in (self.username, new_user):
                    continue
                # Encontrar o nó regenerado mais baixo no caminho deste membro
                member_leaf = self._get_member_leaf(state, member_username)
                if member_leaf is None:
                    continue
                member_path = self._get_path(member_leaf)
                # Nó de intersecção: o mais baixo do caminho do membro que está em path_secrets
                intersect_node = None
                for node in reversed(member_path):  # reversed = do mais baixo ao mais alto
                    if node in path_secrets:
                        intersect_node = node
                        break
                if intersect_node is None:
                    continue
                # Cifrar o segredo desse nó para o membro
                member_enc_pub = self._get_member_enc_pub(state, member_username)
                if not member_enc_pub:
                    continue
                blob = self.encrypt_group_key_for_member(
                    json.dumps({
                        "node_index": intersect_node,
                        "node_secret": base64.b64encode(path_secrets[intersect_node]).decode('utf-8'),
                        "epoch": state["epoch"]
                    }).encode('utf-8'),
                    member_enc_pub
                )
                member_key_packages.append({"username": member_username, "encrypted_blob": blob})

            # KeyPackage para o novo membro (caminho completo até raiz)
            secrets_for_new = {
                str(k): base64.b64encode(v).decode('utf-8')
                for k, v in path_secrets.items()
                if k in self._get_path(new_leaf_idx)
            }
            blob_new = self.encrypt_group_key_for_member(
                json.dumps({
                    "leaf_index": new_leaf_idx,
                    "total_leaves": state["total_leaves"],
                    "path_secrets": secrets_for_new
                }).encode('utf-8'),
                new_user_enc_pub_b64
            )

            pub_tree_update = {
                str(k): base64.b64encode(v).decode('utf-8')
                for k, v in state["tree_pub_keys"].items()
                if k in path_secrets or k == new_leaf_idx
            }

            return {
                "room_name": room,
                "username": new_user,
                "epoch": state["epoch"],
                "total_leaves": state["total_leaves"],
                "public_tree": pub_tree_update,
                "key_packages": [{"username": new_user, "encrypted_blob": blob_new, "leaf_index": new_leaf_idx}],
                "member_key_packages": member_key_packages,  # novo campo
            }
        except:
            traceback.print_exc()
            return {}

    def _get_member_leaf(self, state: dict, member_username: str) -> Optional[int]:
        members = state.get("members_cache", [])
        if member_username not in members:
            return None
        return state["total_leaves"] + members.index(member_username)

    def _get_member_enc_pub(self, state: dict, member_username: str) -> Optional[str]:
        leaf = self._get_member_leaf(state, member_username)
        if leaf is None:
            return None
        pub_bytes = state["tree_pub_keys"].get(leaf)
        if not pub_bytes:
            return None
        return base64.b64encode(pub_bytes).decode('utf-8')

    def process_tree_update(self, room: str, payload: dict, password_kdf: bytes) -> bool:
        if room not in self.group_states: return False
        try:
            state = self.group_states[room]
            state["tree_pub_keys"].update({int(k): base64.b64decode(v) for k,v in payload["public_keys"].items()})
            if "total_leaves" in payload: state["total_leaves"] = payload["total_leaves"]
            if "members" in payload: state["members_cache"] = payload["members"]
            
            curr, path, updates = state["my_leaf_index"], self._get_path(state["my_leaf_index"]), payload.get("path_updates", {})
            for parent in path:
                upd = updates.get(str(parent))
                if upd and upd.get("from_node") == (curr ^ 1):
                    shared = x25519.X25519PrivateKey.from_private_bytes(state["tree_priv_keys"][curr]).exchange(x25519.X25519PublicKey.from_public_bytes(state["tree_pub_keys"][upd["from_node"]]))
                    key = HKDF(hashes.SHA256(), 32, None, f"TreeUpdate:{parent}".encode()).derive(shared)
                    state["tree_priv_keys"][parent] = symmetric.decrypt(key, base64.b64decode(upd["content"]), base64.b64decode(upd["nonce"]), base64.b64decode(upd["tag"]))
                curr = parent
            state["epoch"] = payload["new_epoch"]
            if 1 in state["tree_priv_keys"]:
                state["group_key"] = self.derive_group_key(state["tree_priv_keys"][1], state["epoch"])
                self._save_group_states(password_kdf)
                return True
            return False
        except: return False
