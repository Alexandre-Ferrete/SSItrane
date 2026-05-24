import os
import sqlite3
from typing import Optional, List, Dict, Any


class Storage:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "server.db")
        self.conn: Optional[sqlite3.Connection] = None

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

        try:
            self.conn.execute("ALTER TABLE groups ADD COLUMN epoch INTEGER DEFAULT 0")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute("ALTER TABLE groups ADD COLUMN total_leaves INTEGER DEFAULT 0")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute("ALTER TABLE group_messages ADD COLUMN epoch INTEGER DEFAULT 0")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute("ALTER TABLE group_messages ADD COLUMN recipient TEXT")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        try:
            self.conn.execute("ALTER TABLE group_members ADD COLUMN leaf_index INTEGER DEFAULT 0")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

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
            CREATE TABLE IF NOT EXISTS groups (
                name TEXT PRIMARY KEY,
                created_by TEXT NOT NULL,
                epoch INTEGER DEFAULT 0,
                total_leaves INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(username)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_name TEXT NOT NULL,
                username TEXT NOT NULL,
                leaf_index INTEGER NOT NULL,
                active INTEGER DEFAULT 1,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_name, username),
                FOREIGN KEY (group_name) REFERENCES groups(name),
                FOREIGN KEY (username) REFERENCES users(username)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tree_nodes (
                group_name TEXT NOT NULL,
                node_index INTEGER NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (group_name, node_index),
                FOREIGN KEY (group_name) REFERENCES groups(name)
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS group_key_packages (
                group_name TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                username TEXT NOT NULL,
                encrypted_blob BLOB NOT NULL,
                PRIMARY KEY (group_name, epoch, username),
                FOREIGN KEY (group_name) REFERENCES groups(name),
                FOREIGN KEY (username) REFERENCES users(username)
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
                nonce BLOB,
                tag BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_name) REFERENCES groups(name),
                FOREIGN KEY (recipient) REFERENCES users(username)
            )
        """)

        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    # USER FUNCTIONS
    def create_user(self, username: str, password_hash: str) -> bool:
        try:
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
    def add_device(self, username: str, public_key: bytes, certificate: bytes, salt: bytes, encryption_key: bytes = None) -> bool:
        try:
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
            "SELECT id, public_key, certificate, encryption_key, salt, created_at, last_login FROM user_devices WHERE username = ? ORDER BY last_login DESC",
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
        self.conn.execute(
            "UPDATE user_devices SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (device_id,)
        )
        self.conn.commit()

    def update_device_encryption_key(self, device_id: int, encryption_key: bytes) -> bool:
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
        self.conn.execute("DELETE FROM offline_messages WHERE recipient = ?", (username,))
        self.conn.execute("DELETE FROM offline_messages WHERE sender = ?", (username,))
        self.conn.execute("DELETE FROM group_members WHERE username = ?", (username,))
        self.conn.execute("DELETE FROM group_key_packages WHERE username = ?", (username,))
        self.conn.execute("DELETE FROM user_devices WHERE username = ?", (username,))
        cursor = self.conn.execute("DELETE FROM users WHERE username = ?", (username,))
        self.conn.commit()
        return cursor.rowcount > 0

    def purge_all(self) -> bool:
        self.conn.execute("DELETE FROM offline_messages")
        self.conn.execute("DELETE FROM group_members")
        self.conn.execute("DELETE FROM group_key_packages")
        self.conn.execute("DELETE FROM groups")
        self.conn.execute("DELETE FROM tree_nodes")
        self.conn.execute("DELETE FROM group_messages")
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
                          device_id: Optional[int] = None, ephemeral_key: Optional[bytes] = None) -> int:
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

    # GROUP FUNCTIONS
    def create_group(self, name: str, created_by: str, total_leaves: int) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO groups (name, created_by, epoch, total_leaves) VALUES (?, ?, 0, ?)",
                (name, created_by, total_leaves)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def update_group_epoch(self, group_name: str, new_epoch: int):
        self.conn.execute(
            "UPDATE groups SET epoch = ? WHERE name = ?",
            (new_epoch, group_name)
        )
        self.conn.commit()

    def get_group(self, name: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute("SELECT name, created_by, epoch, total_leaves FROM groups WHERE name = ?", (name,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_user_groups(self, username: str) -> List[str]:
        cursor = self.conn.execute(
            "SELECT group_name FROM group_members WHERE username = ? AND active = 1",
            (username,)
        )
        return [row[0] for row in cursor.fetchall()]

    # GROUP MEMBER FUNCTIONS
    def add_group_member(self, group_name: str, username: str, leaf_index: int) -> bool:
        try:
            # Mark active and set leaf_index
            self.conn.execute("""
                INSERT INTO group_members (group_name, username, leaf_index, active) 
                VALUES (?, ?, ?, 1)
                ON CONFLICT(group_name, username) DO UPDATE SET active=1, leaf_index=excluded.leaf_index
            """, (group_name, username, leaf_index))
            self.conn.commit()
            return True
        except sqlite3.Error:
            return False

    def remove_group_member(self, group_name: str, username: str) -> bool:
        self.conn.execute(
            "UPDATE group_members SET active = 0 WHERE group_name = ? AND username = ?",
            (group_name, username)
        )
        self.conn.commit()
        return True

    def get_group_members(self, group_name: str, only_active: bool = True) -> List[Dict[str, Any]]:
        query = "SELECT username, leaf_index FROM group_members WHERE group_name = ?"
        if only_active:
            query += " AND active = 1"
        cursor = self.conn.execute(query, (group_name,))
        return [dict(row) for row in cursor.fetchall()]

    def is_group_member(self, group_name: str, username: str) -> bool:
        cursor = self.conn.execute(
            "SELECT 1 FROM group_members WHERE group_name = ? AND username = ? AND active = 1",
            (group_name, username)
        )
        return cursor.fetchone() is not None

    # TREE STATE FUNCTIONS
    def store_tree_node(self, group_name: str, node_index: int, public_key: bytes):
        self.conn.execute("""
            INSERT INTO tree_nodes (group_name, node_index, public_key) 
            VALUES (?, ?, ?)
            ON CONFLICT(group_name, node_index) DO UPDATE SET public_key=excluded.public_key
        """, (group_name, node_index, public_key))
        self.conn.commit()

    def get_tree_nodes(self, group_name: str) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT node_index, public_key FROM tree_nodes WHERE group_name = ?",
            (group_name,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def store_group_key_package(self, group_name: str, epoch: int, username: str, encrypted_blob: bytes):
        self.conn.execute("""
            INSERT INTO group_key_packages (group_name, epoch, username, encrypted_blob) 
            VALUES (?, ?, ?, ?)
            ON CONFLICT(group_name, epoch, username) DO UPDATE SET encrypted_blob=excluded.encrypted_blob
        """, (group_name, epoch, username, encrypted_blob))
        self.conn.commit()

    def get_key_packages_for_user(self, username: str) -> List[Dict[str, Any]]:
        # Returns current key packages for all groups user is in
        cursor = self.conn.execute("""
            SELECT kp.group_name, kp.epoch, kp.encrypted_blob
            FROM group_key_packages kp
            JOIN groups g ON kp.group_name = g.name
            WHERE kp.username = ? AND kp.epoch = g.epoch
        """, (username,))
        return [dict(row) for row in cursor.fetchall()]

    # GROUP MESSAGE FUNCTIONS
    def store_group_message(self, group_name: str, recipient: str, sender: str, epoch: int, content: bytes, nonce: bytes, tag: bytes):
        self.conn.execute(
            "INSERT INTO group_messages (group_name, recipient, sender, epoch, encrypted_content, nonce, tag) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (group_name, recipient, sender, epoch, content, nonce, tag)
        )
        self.conn.commit()

    def get_group_messages_for_user(self, username: str) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT id, group_name, sender, epoch, encrypted_content as content, nonce, tag, created_at FROM group_messages WHERE recipient = ? ORDER BY created_at ASC",
            (username,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def clear_group_messages_for_user(self, username: str):
        self.conn.execute("DELETE FROM group_messages WHERE recipient = ?", (username,))
        self.conn.commit()

    def get_group_messages(self, group_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT sender, epoch, encrypted_content as content, nonce, tag, created_at FROM group_messages WHERE group_name = ? ORDER BY created_at DESC LIMIT ?",
            (group_name, limit)
        )
        return [dict(row) for row in cursor.fetchall()]
