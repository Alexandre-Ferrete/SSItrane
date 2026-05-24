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
                    "epoch": state["epoch"],
                    "my_leaf_index": state["my_leaf_index"],
                    "total_leaves": state["total_leaves"],
                    "group_key": base64.b64encode(state["group_key"]).decode(),
                    "creator": state.get("creator", ""),
                    "tree_priv": {str(k): base64.b64encode(v).decode() for k, v in state["tree_priv"].items()},
                    "tree_pub":  {str(k): base64.b64encode(v).decode() for k, v in state["tree_pub"].items()},
                    "members": state.get("members", []),
                    "ratchets": {k: base64.b64encode(v).decode() for k, v in state.get("ratchets", {}).items()},
                }
            c, n, t = symmetric.encrypt(password_kdf, json.dumps(serializable).encode())
            with open(os.path.join(self.data_dir, f"{self.username}_groups.json.enc"), "wb") as f:
                f.write(n + t + c)
        except: pass

    def _load_group_states(self, password_kdf: bytes):
        path = os.path.join(self.data_dir, f"{self.username}_groups.json.enc")
        if not os.path.exists(path): return
        try:
            with open(path, "rb") as f:
                raw = f.read()
                if len(raw) < 28: return
                n, t, c = raw[:12], raw[12:28], raw[28:]
            data = json.loads(symmetric.decrypt(password_kdf, c, n, t).decode())
            for room, s in data.items():
                self.group_states[room] = {
                    "epoch": s["epoch"],
                    "my_leaf_index": s["my_leaf_index"],
                    "total_leaves": s["total_leaves"],
                    "group_key": base64.b64decode(s["group_key"]),
                    "creator": s.get("creator", ""),
                    "tree_priv": {int(k): base64.b64decode(v) for k, v in s["tree_priv"].items()},
                    "tree_pub":  {int(k): base64.b64decode(v) for k, v in s["tree_pub"].items()},
                    "members": s.get("members", []),
                    "ratchets": {k: base64.b64decode(v) for k, v in s.get("ratchets", {}).items()},
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
    #
    # 1-indexed binary tree: root=1, children of i are 2i and 2i+1,
    # sibling of i is i^1, parent of i is i//2.
    # Leaves are at indices [total_leaves .. 2*total_leaves-1].
    # Internal nodes are at [1 .. total_leaves-1].
    #
    # group_state = {
    #   "epoch": int, "my_leaf_index": int, "total_leaves": int,
    #   "group_key": bytes, "creator": str,
    #   "tree_priv": {int: bytes},   # private keys for OWN direct path only
    #   "tree_pub":  {int: bytes},   # public keys for all known nodes
    #   "members": [str|None, ...],  # index i → leaf total_leaves+i; None = removed
    # }

    def _get_path(self, idx: int) -> List[int]:
        """Return [parent, grandparent, ..., 1] for node idx."""
        path = []
        while idx > 1:
            idx //= 2
            path.append(idx)
        return path

    def derive_group_key(self, root_secret: bytes, epoch: int) -> bytes:
        return HKDF(hashes.SHA256(), 32, epoch.to_bytes(4, 'big'), b"GroupKey").derive(root_secret)

    def _get_member_leaf(self, state: dict, username: str) -> Optional[int]:
        members = state.get("members", [])
        for i, name in enumerate(members):
            if name == username:
                return state["total_leaves"] + i
        return None

    def _get_member_enc_pub(self, state: dict, username: str) -> Optional[str]:
        leaf = self._get_member_leaf(state, username)
        if leaf is None:
            return None
        pub = state["tree_pub"].get(leaf)
        return base64.b64encode(pub).decode() if pub else None

    def encrypt_group_key_for_member(self, data: bytes, pub_b64: str) -> dict:
        try:
            pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
            eph = x25519.X25519PrivateKey.generate()
            key = HKDF(hashes.SHA256(), 32, None, b"GroupKeyDistribution").derive(eph.exchange(pub))
            c, n, t = symmetric.encrypt(key, data)
            return {
                "content": base64.b64encode(c).decode(),
                "nonce":   base64.b64encode(n).decode(),
                "tag":     base64.b64encode(t).decode(),
                "ephemeral_key": base64.b64encode(
                    eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                ).decode(),
            }
        except:
            return {}

    def initialize_tree_as_creator(self, room: str, members: List[Dict[str, str]], password_kdf: bytes) -> dict:
        """
        Build a TreeKEM tree for `members` (list of {username, enc_pub_key}).
        The creator generates random X25519 keypairs for ALL internal nodes.
        Every non-creator member receives an encrypted KeyPackage with the
        private keys of the nodes on their direct path to the root.
        """
        try:
            n = len(members)
            if n < 2:
                return {}
            # Always leave at least one empty leaf slot so the first /group add works.
            # ceil(log2(n)) would equal n for powers-of-2, filling the tree immediately.
            depth = max(2, math.ceil(math.log2(n + 1)))
            total_leaves = 2 ** depth

            # ── leaf pub keys ────────────────────────────────────────────────
            tree_pub: Dict[int, bytes] = {}
            my_leaf = -1
            for i, m in enumerate(members):
                leaf = total_leaves + i
                tree_pub[leaf] = base64.b64decode(m["enc_pub_key"])
                if m["username"] == self.username:
                    my_leaf = leaf

            if my_leaf < 0:
                return {}

            # ── random X25519 keypairs for ALL internal nodes ────────────────
            tree_priv: Dict[int, bytes] = {}
            for node in range(1, total_leaves):
                priv = x25519.X25519PrivateKey.generate()
                priv_b = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                tree_priv[node] = priv_b
                tree_pub[node]  = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

            # ── creator's own state ──────────────────────────────────────────
            my_enc_priv_b = self.encryption_priv_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
            my_tree_priv = {my_leaf: my_enc_priv_b}
            for node in self._get_path(my_leaf):
                my_tree_priv[node] = tree_priv[node]

            group_key = self.derive_group_key(tree_priv[1], 0)
            self.group_states[room] = {
                "epoch": 0,
                "my_leaf_index": my_leaf,
                "total_leaves": total_leaves,
                "group_key": group_key,
                "creator": self.username,
                "tree_priv": my_tree_priv,
                "tree_pub": dict(tree_pub),
                "members": [m["username"] for m in members],
                "ratchets": {},
            }
            self._save_group_states(password_kdf)

            # ── KeyPackages for every non-creator member ─────────────────────
            key_packages = []
            for i, m in enumerate(members):
                if m["username"] == self.username:
                    continue
                leaf = total_leaves + i
                path_secrets = {str(node): base64.b64encode(tree_priv[node]).decode()
                                for node in self._get_path(leaf)}
                blob_data = json.dumps({
                    "leaf_index": leaf,
                    "total_leaves": total_leaves,
                    "path_secrets": path_secrets,
                    "creator": self.username,
                }).encode()
                blob = self.encrypt_group_key_for_member(blob_data, m["enc_pub_key"])
                key_packages.append({"username": m["username"], "encrypted_blob": blob})

            # Public tree: only internal node public keys go to the server
            public_tree = {str(k): base64.b64encode(v).decode()
                           for k, v in tree_pub.items() if k < total_leaves}

            return {
                "room_name": room,
                "total_leaves": total_leaves,
                "public_tree": public_tree,
                "key_packages": key_packages,
                "members": [m["username"] for m in members],
            }
        except Exception:
            traceback.print_exc()
            return {}

    def process_key_package(self, room: str, epoch: int, blob: dict, password_kdf: bytes) -> bool:
        """Decrypt a KeyPackage and restore local tree state."""
        # Only skip if already at a HIGHER epoch — never skip equal epoch, because
        # GROUP_UPDATE may have advanced the epoch counter but not yet set the new group_key.
        if room in self.group_states and self.group_states[room]["epoch"] > epoch:
            return True
        try:
            eph_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(blob["ephemeral_key"]))
            key = HKDF(hashes.SHA256(), 32, None, b"GroupKeyDistribution").derive(
                self.encryption_priv_key.exchange(eph_pub)
            )
            plaintext = symmetric.decrypt(
                key,
                base64.b64decode(blob["content"]),
                base64.b64decode(blob["nonce"]),
                base64.b64decode(blob["tag"]),
            )
            data = json.loads(plaintext.decode())
            leaf = data["leaf_index"]
            total_leaves = data["total_leaves"]
            path_secrets = {int(k): base64.b64decode(v) for k, v in data["path_secrets"].items()}

            my_enc_priv_b = self.encryption_priv_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
            # Merge: start from existing path keys, overlay only the changed nodes
            existing = self.group_states.get(room, {})
            merged_priv = dict(existing.get("tree_priv", {}))
            merged_priv[leaf] = my_enc_priv_b
            merged_priv.update(path_secrets)

            root_secret = merged_priv.get(1)
            if root_secret is None:
                return False

            self.group_states[room] = {
                "epoch": epoch,
                "my_leaf_index": leaf,
                "total_leaves": total_leaves,
                "group_key": self.derive_group_key(root_secret, epoch),
                "creator": data.get("creator", existing.get("creator", "")),
                "tree_priv": merged_priv,
                "tree_pub": existing.get("tree_pub", {}),
                "members": existing.get("members", []),
                "ratchets": {},  # new epoch → new group_key → all ratchet init keys change
            }
            self._save_group_states(password_kdf)
            return True
        except Exception:
            traceback.print_exc()
            return False

    def prepare_add_update(self, room: str, new_user: str, new_user_enc_pub_b64: str, password_kdf: bytes) -> dict:
        """
        Admin adds a new member.  Regenerates the path from the new leaf to root
        with fresh random keys (new epoch).  Sends:
          - A full KeyPackage to the new member.
          - Updated path secrets to each existing member whose direct path
            intersects the regenerated path.
        """
        if room not in self.group_states:
            return {}
        try:
            state = self.group_states[room]
            members: List[Optional[str]] = list(state.get("members", []))
            if new_user in members:
                return {}

            total_leaves = state["total_leaves"]
            # Reuse a vacant (None) slot if one exists, otherwise append at the end
            try:
                slot = members.index(None)
                new_leaf = total_leaves + slot
            except ValueError:
                slot = len(members)
                new_leaf = total_leaves + slot

            if new_leaf >= total_leaves * 2:
                print("[!] Grupo cheio. Não é possível adicionar mais membros.")
                return {}

            # Store new member's leaf pub key
            new_pub_b = base64.b64decode(new_user_enc_pub_b64)
            state["tree_pub"][new_leaf] = new_pub_b

            # Regenerate path from new_leaf to root with fresh random keys
            path = self._get_path(new_leaf)  # [parent, gp, ..., 1]
            updated_pub: Dict[int, bytes] = {}
            for node in path:
                priv = x25519.X25519PrivateKey.generate()
                priv_b = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                pub_b  = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                state["tree_priv"][node] = priv_b
                state["tree_pub"][node]  = pub_b
                updated_pub[node] = pub_b

            new_epoch = state["epoch"] + 1
            state["epoch"] = new_epoch
            state["group_key"] = self.derive_group_key(state["tree_priv"][1], new_epoch)
            state["ratchets"] = {}  # new group_key → reset all per-sender ratchets
            if slot < len(members):
                members[slot] = new_user   # fill the vacant slot
            else:
                members.append(new_user)   # extend the list
            state["members"] = members
            self._save_group_states(password_kdf)

            updated_set = set(path)

            # Full KeyPackage for the new member
            path_secrets_new = {str(node): base64.b64encode(state["tree_priv"][node]).decode()
                                for node in path}
            blob_new = self.encrypt_group_key_for_member(
                json.dumps({
                    "leaf_index": new_leaf,
                    "total_leaves": total_leaves,
                    "path_secrets": path_secrets_new,
                    "creator": state.get("creator", ""),
                }).encode(),
                new_user_enc_pub_b64,
            )

            # Updated path secrets for existing members whose path crosses the regenerated nodes
            member_key_packages = []
            for i, username in enumerate(members[:-1]):          # exclude new member
                if username is None or username == self.username:
                    continue
                leaf_i = total_leaves + i
                member_path_set = set(self._get_path(leaf_i))
                intersecting = member_path_set & updated_set
                if not intersecting:
                    continue
                # Only send path secrets for nodes on BOTH the new path and M's own path
                relevant = {str(node): base64.b64encode(state["tree_priv"][node]).decode()
                            for node in path if node in member_path_set}
                member_pub = state["tree_pub"].get(leaf_i)
                if not member_pub:
                    continue
                blob_m = self.encrypt_group_key_for_member(
                    json.dumps({
                        "leaf_index": leaf_i,
                        "total_leaves": total_leaves,
                        "path_secrets": relevant,
                        "creator": state.get("creator", ""),
                    }).encode(),
                    base64.b64encode(member_pub).decode(),
                )
                member_key_packages.append({"username": username, "encrypted_blob": blob_m})

            return {
                "room_name": room,
                "username": new_user,
                "epoch": new_epoch,
                "new_leaf": new_leaf,
                "total_leaves": total_leaves,
                "public_tree": {str(k): base64.b64encode(v).decode() for k, v in updated_pub.items()},
                "key_packages": [{"username": new_user, "encrypted_blob": blob_new, "leaf_index": new_leaf}],
                "member_key_packages": member_key_packages,
            }
        except Exception:
            traceback.print_exc()
            return {}

    def prepare_remove_update(self, room: str, removed_user: str, password_kdf: bytes) -> dict:
        """
        Admin removes a member.  Regenerates ALL nodes on the removed member's
        direct path with brand-new random keys, ensuring forward secrecy.
        Sends updated path secrets to every remaining member whose path intersects.
        """
        if room not in self.group_states:
            return {}
        try:
            state = self.group_states[room]
            members: List[Optional[str]] = list(state.get("members", []))
            if removed_user not in members:
                return {}

            total_leaves = state["total_leaves"]
            removed_idx  = members.index(removed_user)
            removed_leaf = total_leaves + removed_idx

            # Regenerate ALL nodes on the removed member's path (forward secrecy)
            path = self._get_path(removed_leaf)
            updated_pub: Dict[int, bytes] = {}
            for node in path:
                priv = x25519.X25519PrivateKey.generate()
                priv_b = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                pub_b  = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                state["tree_priv"][node] = priv_b
                state["tree_pub"][node]  = pub_b
                updated_pub[node] = pub_b

            # Mark the leaf as empty
            members[removed_idx] = None
            state["members"] = members
            state["tree_pub"].pop(removed_leaf, None)
            state["tree_priv"].pop(removed_leaf, None)

            new_epoch = state["epoch"] + 1
            state["epoch"] = new_epoch
            state["group_key"] = self.derive_group_key(state["tree_priv"][1], new_epoch)
            state["ratchets"] = {}  # new group_key → reset all per-sender ratchets
            self._save_group_states(password_kdf)

            updated_set = set(path)

            # KeyPackages for all remaining members whose path crosses the regenerated nodes
            member_key_packages = []
            for i, username in enumerate(members):
                if username is None or username == self.username:
                    continue
                leaf_i = total_leaves + i
                member_path_set = set(self._get_path(leaf_i))
                if not (member_path_set & updated_set):
                    continue
                # Only include nodes on both the regenerated path and M's own path
                relevant = {str(node): base64.b64encode(state["tree_priv"][node]).decode()
                            for node in path if node in member_path_set}
                member_pub = state["tree_pub"].get(leaf_i)
                if not member_pub:
                    continue
                blob_m = self.encrypt_group_key_for_member(
                    json.dumps({
                        "leaf_index": leaf_i,
                        "total_leaves": total_leaves,
                        "path_secrets": relevant,
                        "creator": state.get("creator", ""),
                    }).encode(),
                    base64.b64encode(member_pub).decode(),
                )
                member_key_packages.append({"username": username, "encrypted_blob": blob_m})

            return {
                "room_name": room,
                "removed_user": removed_user,
                "removed_leaf": removed_leaf,
                "epoch": new_epoch,
                "total_leaves": total_leaves,
                "public_tree": {str(k): base64.b64encode(v).decode() for k, v in updated_pub.items()},
                "member_key_packages": member_key_packages,
            }
        except Exception:
            traceback.print_exc()
            return {}

    def _sender_ratchet(self, state: dict, sender: str) -> bytes:
        """Return the current ratchet key for `sender`, initialising it if needed."""
        ratchets = state.setdefault("ratchets", {})
        if sender not in ratchets:
            # Derive a unique initial key per sender from the shared group_key
            ratchets[sender] = HKDF(hashes.SHA256(), 32, sender.encode(), b"GroupRatchetInit").derive(state["group_key"])
        return ratchets[sender]

    def encrypt_for_group(self, room: str, text: str, password_kdf: Optional[bytes] = None) -> Optional[dict]:
        if room not in self.group_states:
            return None
        try:
            state = self.group_states[room]
            me = self.username or "unknown"
            msg_key = self._sender_ratchet(state, me)
            c, n, t = symmetric.encrypt(msg_key, text.encode())
            # Advance the ratchet — the used key is now gone (forward secrecy per message)
            state["ratchets"][me] = HKDF(hashes.SHA256(), 32, None, b"GroupRatchet").derive(msg_key)
            if password_kdf:
                self._save_group_states(password_kdf)
            return {
                "room_name": room,
                "epoch":   state["epoch"],
                "content": base64.b64encode(c).decode(),
                "nonce":   base64.b64encode(n).decode(),
                "tag":     base64.b64encode(t).decode(),
            }
        except:
            return None

    def decrypt_from_group(self, room: str, epoch: int, sender: str, payload: dict, password_kdf: Optional[bytes] = None) -> Optional[str]:
        if room not in self.group_states:
            return None
        state = self.group_states[room]
        if epoch != state["epoch"]:
            return f"(Epoch desatualizado: recebido {epoch}, atual {state['epoch']})"
        try:
            msg_key = self._sender_ratchet(state, sender)
            plaintext = symmetric.decrypt(
                msg_key,
                base64.b64decode(payload["content"]),
                base64.b64decode(payload["nonce"]),
                base64.b64decode(payload["tag"]),
            ).decode()
            # Advance the ratchet for this sender
            state["ratchets"][sender] = HKDF(hashes.SHA256(), 32, None, b"GroupRatchet").derive(msg_key)
            if password_kdf:
                self._save_group_states(password_kdf)
            return plaintext
        except Exception as e:
            return f"(Erro de decifração: {e})"

    # kept for back-compat; real add now goes through prepare_add_update
    def add_member_to_tree(self, room: str, new_user: str, new_user_enc_pub_b64: str, password_kdf: bytes) -> dict:
        return self.prepare_add_update(room, new_user, new_user_enc_pub_b64, password_kdf)

    def process_tree_update(self, room: str, payload: dict, password_kdf: bytes) -> bool:
        """Apply a GROUP_UPDATE from the server (updated public tree + new epoch)."""
        if room not in self.group_states:
            return False
        try:
            state = self.group_states[room]
            # Update public tree with the changed nodes
            for k, v in payload.get("public_tree", {}).items():
                state["tree_pub"][int(k)] = base64.b64decode(v)
            if "total_leaves" in payload:
                state["total_leaves"] = payload["total_leaves"]
            if "members" in payload:
                state["members"] = payload["members"]
            # The new group_key will be set when the GROUP_KEY_PACKAGE arrives;
            # epoch is updated here so messages with the new epoch are accepted.
            state["epoch"] = payload.get("epoch", state["epoch"])
            self._save_group_states(password_kdf)
            return True
        except Exception:
            traceback.print_exc()
            return False
