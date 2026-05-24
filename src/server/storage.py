import os
import sqlite3
from typing import Optional, List, Dict, Any


import os
import sqlite3
import threading
from typing import Optional, List, Dict, Any


class Storage:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "server.db")
        self.conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()          # ← lock global para sqlite

    def initialize(self):
        os.makedirs(self.data_dir, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
        self._migrate()

    def _migrate(self):
        try:
            self.conn.execute("ALTER TABLE offline_messages ADD COLUMN device_id INTEGER")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute("ALTER TABLE offline_messages ADD COLUMN message_key BLOB")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute("ALTER TABLE user_devices ADD COLUMN encryption_key BLOB")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute("SELECT id FROM user_devices WHERE username = 'test'")
        except sqlite3.OperationalError:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS user_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    certificate BLOB NOT NULL,
                    encryption_key BLOB,
                    salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES users(username),
                    UNIQUE(username, public_key)
                )
            """)
            self.conn.commit()

    def _create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS user_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                public_key BLOB NOT NULL,
                certificate BLOB NOT NULL,
                encryption_key BLOB,
                salt BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username),
                UNIQUE(username, public_key)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                nonce BLOB,
                tag BLOB,
                FOREIGN KEY (device_id) REFERENCES user_devices(id)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS rooms (
                name TEXT PRIMARY KEY,
                created_by TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(username)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS room_members (
                room_name TEXT NOT NULL,
                username TEXT NOT NULL,
                PRIMARY KEY (room_name, username),
                FOREIGN KEY (room_name) REFERENCES rooms(name),
                FOREIGN KEY (username) REFERENCES users(username)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                name TEXT PRIMARY KEY,
                created_by TEXT NOT NULL,
                epoch INTEGER NOT NULL DEFAULT 0,
                total_leaves INTEGER NOT NULL DEFAULT 4
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_name TEXT NOT NULL,
                username TEXT NOT NULL,
                leaf_index INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (group_name, username)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tree_nodes (
                group_name TEXT NOT NULL,
                node_index INTEGER NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (group_name, node_index)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS group_key_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_name TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                username TEXT NOT NULL,
                encrypted_blob BLOB NOT NULL
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_name TEXT NOT NULL,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                encrypted_content BLOB NOT NULL,
                nonce BLOB NOT NULL,
                tag BLOB NOT NULL
            )
        """)

        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    # USER FUNCTIONS
    def create_user(self, username: str, password_hash: str) -> bool:
        try:
            with self._lock:
                self.conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def get_user_with_devices(self, username: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        if row:
            user = dict(row)
            user["devices"] = self.get_devices(username)
            return user
        return None

    # DEVICE FUNCTIONS
    def add_device(self, username: str, public_key: bytes, certificate: bytes,
                   salt: bytes, encryption_key: bytes = None) -> bool:
        try:
            with self._lock:
                self.conn.execute(
                    "INSERT INTO user_devices (username, public_key, certificate, salt, encryption_key) VALUES (?, ?, ?, ?, ?)",
                    (username, public_key, certificate, salt, encryption_key)
                )
                self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_devices(self, username: str) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT id, public_key, certificate, encryption_key, salt, created_at, last_login FROM user_devices WHERE username = ?",
            (username,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_device(self, username: str, public_key: bytes) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT id, public_key, certificate, salt, created_at, last_login FROM user_devices WHERE username = ? AND public_key = ?",
            (username, public_key)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def get_device_by_id(self, device_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT id, username, public_key, certificate, salt, created_at, last_login FROM user_devices WHERE id = ?",
            (device_id,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def update_last_login(self, device_id: int):
        with self._lock:
            self.conn.execute(
                "UPDATE user_devices SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (device_id,)
            )
            self.conn.commit()

    def update_device_encryption_key(self, device_id: int, encryption_key: bytes) -> bool:
        with self._lock:
            cursor = self.conn.execute(
                "UPDATE user_devices SET encryption_key = ? WHERE id = ?",
                (encryption_key, device_id)
            )
            self.conn.commit()
        return cursor.rowcount > 0

    def delete_device(self, device_id: int) -> bool:
        cursor = self.conn.execute("DELETE FROM user_devices WHERE id = ?", (device_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_public_keys(self, username: str) -> List[bytes]:
        cursor = self.conn.execute(
            "SELECT public_key FROM user_devices WHERE username = ?",
            (username,)
        )
        return [row[0] for row in cursor.fetchall()]

    def delete_user(self, username: str) -> bool:
        with self._lock:
            self.conn.execute("DELETE FROM offline_messages WHERE recipient = ?", (username,))
            self.conn.execute("DELETE FROM offline_messages WHERE sender = ?", (username,))
            self.conn.execute("DELETE FROM room_members WHERE username = ?", (username,))
            self.conn.execute("DELETE FROM user_devices WHERE username = ?", (username,))
            cursor = self.conn.execute("DELETE FROM users WHERE username = ?", (username,))
            self.conn.commit()
        return cursor.rowcount > 0

    def purge_all(self) -> bool:
        self.conn.execute("DELETE FROM offline_messages")
        self.conn.execute("DELETE FROM room_members")
        self.conn.execute("DELETE FROM rooms")
        self.conn.execute("DELETE FROM user_devices")
        self.conn.execute("DELETE FROM users")
        self.conn.commit()
        return True

    def list_users(self) -> List[Dict[str, Any]]:
        # Lista todos os utilizadores
        cursor = self.conn.execute("SELECT username FROM users")
        return [{"username": row[0]} for row in cursor.fetchall()]

    # OFFLINE MESSAGE FUNCTIONS
    def store_offline_message(self, recipient: str, sender: str, content: bytes,
                              nonce: Optional[bytes] = None, tag: Optional[bytes] = None,
                              device_id: Optional[int] = None,
                              ephemeral_key: Optional[bytes] = None) -> int:
        with self._lock:
            cursor = self.conn.execute(
                "INSERT INTO offline_messages (device_id, recipient, sender, encrypted_content, nonce, tag, message_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (device_id, recipient, sender, content, nonce, tag, ephemeral_key)
            )
            self.conn.commit()
        return cursor.lastrowid

    def get_offline_messages(self, recipient: str, device_id: Optional[int] = None) -> List[Dict[str, Any]]:
        if device_id:
            cursor = self.conn.execute(
                "SELECT id, device_id, sender, encrypted_content, nonce, tag, message_key as ephemeral_key FROM offline_messages WHERE recipient = ? AND device_id = ?",
                (recipient, device_id)
            )
        else:
            cursor = self.conn.execute(
                "SELECT id, device_id, sender, encrypted_content, nonce, tag, message_key as ephemeral_key FROM offline_messages WHERE recipient = ?",
                (recipient,)
            )

        messages = []
        for row in cursor.fetchall():
            messages.append({
                "id": row["id"],
                "device_id": row["device_id"],
                "sender": row["sender"],
                "content": row["encrypted_content"],
                "nonce": row["nonce"],
                "tag": row["tag"],
                "ephemeral_key": row["ephemeral_key"]
            })

        return messages

    def get_offline_messages_by_device(self, device_id: int) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT id, device_id, sender, encrypted_content, nonce, tag, message_key as ephemeral_key FROM offline_messages WHERE device_id = ?",
            (device_id,)
        )

        messages = []
        for row in cursor.fetchall():
            messages.append({
                "id": row["id"],
                "device_id": row["device_id"],
                "sender": row["sender"],
                "content": row["encrypted_content"],
                "nonce": row["nonce"],
                "tag": row["tag"],
                "ephemeral_key": row["ephemeral_key"]
            })

        return messages

    def delete_offline_message(self, message_id: int) -> bool:
        # Apaga uma mensagem offline
        cursor = self.conn.execute("DELETE FROM offline_messages WHERE id = ?", (message_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def clear_offline_messages(self, recipient: str, device_id: Optional[int] = None) -> int:
        if device_id:
            cursor = self.conn.execute("DELETE FROM offline_messages WHERE recipient = ? AND device_id = ?", (recipient, device_id))
        else:
            cursor = self.conn.execute("DELETE FROM offline_messages WHERE recipient = ?", (recipient,))
        self.conn.commit()
        return cursor.rowcount

    def clear_offline_messages_by_device(self, device_id: int) -> int:
        cursor = self.conn.execute("DELETE FROM offline_messages WHERE device_id = ?", (device_id,))
        self.conn.commit()
        return cursor.rowcount

    # ROOM FUNCTIONS
    def create_room(self, name: str, created_by: str) -> bool:
        # Cria nova sala
        try:
            self.conn.execute("INSERT INTO rooms (name, created_by) VALUES (?, ?)", (name, created_by))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def delete_room(self, name: str) -> bool:
        # Apaga sala e os seus membros
        self.conn.execute("DELETE FROM room_members WHERE room_name = ?", (name,))
        cursor = self.conn.execute("DELETE FROM rooms WHERE name = ?", (name,))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_room(self, name: str) -> Optional[Dict[str, Any]]:
        # Retorna sala pelo nome
        cursor = self.conn.execute("SELECT name, created_by FROM rooms WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def list_rooms(self) -> List[Dict[str, Any]]:
        # Lista todas as salas
        cursor = self.conn.execute("SELECT name, created_by FROM rooms")
        return [dict(row) for row in cursor.fetchall()]

    # ROOM MEMBER FUNCTIONS
    def add_room_member(self, room_name: str, username: str) -> bool:
        # Adiciona membro a uma sala
        self.conn.execute(
            "INSERT OR IGNORE INTO room_members (room_name, username) VALUES (?, ?)",
            (room_name, username)
        )
        self.conn.commit()
        return True

    def remove_room_member(self, room_name: str, username: str) -> bool:
        # Remove membro de uma sala
        cursor = self.conn.execute(
            "DELETE FROM room_members WHERE room_name = ? AND username = ?",
            (room_name, username)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def get_room_members(self, room_name: str) -> List[str]:
        cursor = self.conn.execute(
            "SELECT username FROM room_members WHERE room_name = ?",
            (room_name,)
        )
        return [row[0] for row in cursor.fetchall()]

    def is_room_member(self, room_name: str, username: str) -> bool:
        # Verifica se utilizador é membro de uma sala
        cursor = self.conn.execute(
            "SELECT 1 FROM room_members WHERE room_name = ? AND username = ?",
            (room_name, username)
        )
        return cursor.fetchone() is not None

    def get_user_rooms(self, username: str) -> List[str]:
        # Retorna salas de um utilizador
        cursor = self.conn.execute(
            "SELECT room_name FROM room_members WHERE username = ?",
            (username,)
        )
        return [row[0] for row in cursor.fetchall()]

    # ── GROUP METHODS ────────────────────────────────────────────────────────

    def create_group(self, name: str, created_by: str, total_leaves: int) -> bool:
        try:
            with self._lock:
                self.conn.execute(
                    "INSERT INTO groups (name, created_by, epoch, total_leaves) VALUES (?, ?, 0, ?)",
                    (name, created_by, total_leaves)
                )
                self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_group(self, group_name: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT name, created_by, epoch, total_leaves FROM groups WHERE name = ?", (group_name,)
        ).fetchone()
        return dict(row) if row else None

    def update_group_epoch(self, group_name: str, epoch: int) -> bool:
        with self._lock:
            cursor = self.conn.execute(
                "UPDATE groups SET epoch = ? WHERE name = ?", (epoch, group_name)
            )
            self.conn.commit()
        return cursor.rowcount > 0

    def store_tree_node(self, group_name: str, node_index: int, public_key: bytes) -> bool:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO tree_nodes (group_name, node_index, public_key) VALUES (?, ?, ?)",
                (group_name, node_index, public_key)
            )
            self.conn.commit()
        return True

    def get_tree_nodes(self, group_name: str) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT node_index, public_key FROM tree_nodes WHERE group_name = ? ORDER BY node_index",
            (group_name,)
        )
        return [{"node_index": row[0], "public_key": row[1]} for row in cursor.fetchall()]

    def add_group_member(self, group_name: str, username: str, leaf_index: int) -> bool:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO group_members (group_name, username, leaf_index, active) VALUES (?, ?, ?, 1)",
                (group_name, username, leaf_index)
            )
            self.conn.commit()
        return True

    def remove_group_member(self, group_name: str, username: str) -> bool:
        with self._lock:
            cursor = self.conn.execute(
                "UPDATE group_members SET active = 0 WHERE group_name = ? AND username = ?",
                (group_name, username)
            )
            self.conn.commit()
        return cursor.rowcount > 0

    def is_group_member(self, group_name: str, username: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM group_members WHERE group_name = ? AND username = ? AND active = 1",
            (group_name, username)
        ).fetchone()
        return row is not None

    def get_group_members(self, group_name: str, only_active: bool = False) -> List[Dict[str, Any]]:
        if only_active:
            cursor = self.conn.execute(
                "SELECT username, leaf_index, active FROM group_members WHERE group_name = ? AND active = 1 ORDER BY leaf_index",
                (group_name,)
            )
        else:
            cursor = self.conn.execute(
                "SELECT username, leaf_index, active FROM group_members WHERE group_name = ? ORDER BY leaf_index",
                (group_name,)
            )
        return [{"username": row[0], "leaf_index": row[1], "active": bool(row[2])} for row in cursor.fetchall()]

    def list_user_groups(self, username: str) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            """SELECT g.name, g.created_by, g.epoch, g.total_leaves
               FROM groups g JOIN group_members gm ON g.name = gm.group_name
               WHERE gm.username = ? AND gm.active = 1""",
            (username,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def store_group_key_package(self, group_name: str, epoch: int, username: str, encrypted_blob: bytes) -> bool:
        with self._lock:
            self.conn.execute(
                "INSERT INTO group_key_packages (group_name, epoch, username, encrypted_blob) VALUES (?, ?, ?, ?)",
                (group_name, epoch, username, encrypted_blob)
            )
            self.conn.commit()
        return True

    def get_key_packages_for_user(self, username: str) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            """SELECT kp.group_name, kp.epoch, kp.encrypted_blob
               FROM group_key_packages kp
               JOIN groups g ON kp.group_name = g.name
               WHERE kp.username = ? AND kp.epoch = g.epoch""",
            (username,)
        )
        return [{"group_name": row[0], "epoch": row[1], "encrypted_blob": row[2]} for row in cursor.fetchall()]

    def delete_key_packages_for_user(self, username: str, group_name: str) -> int:
        with self._lock:
            cursor = self.conn.execute(
                "DELETE FROM group_key_packages WHERE username = ? AND group_name = ?",
                (username, group_name)
            )
            self.conn.commit()
        return cursor.rowcount

    def store_group_message(self, group_name: str, recipient: str, sender: str, epoch: int,
                             content: bytes, nonce: bytes, tag: bytes) -> bool:
        with self._lock:
            self.conn.execute(
                "INSERT INTO group_messages (group_name, recipient, sender, epoch, encrypted_content, nonce, tag) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (group_name, recipient, sender, epoch, content, nonce, tag)
            )
            self.conn.commit()
        return True

    def get_group_messages_for_user(self, username: str) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT id, group_name, sender, epoch, encrypted_content, nonce, tag FROM group_messages WHERE recipient = ? ORDER BY id",
            (username,)
        )
        return [{"id": r[0], "group_name": r[1], "sender": r[2], "epoch": r[3],
                 "content": r[4], "nonce": r[5], "tag": r[6]} for r in cursor.fetchall()]

    def clear_group_messages_for_user(self, username: str) -> int:
        with self._lock:
            cursor = self.conn.execute("DELETE FROM group_messages WHERE recipient = ?", (username,))
            self.conn.commit()
        return cursor.rowcount