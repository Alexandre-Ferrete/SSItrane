"""
Message Types
===========
Defines all message types for client-server communication.
"""

import time
import json
from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


class MessageType(Enum):
    # Fluxo de Sistema (Client <-> Server)
    SERVER_HELLO = "server_hello"
    CLIENT_HELLO = "client_hello"
    REGISTER = "register"
    AUTH = "auth"
    GET_IP = "get_ip"
    GET_USERS = "get_users"
    DISCONNECT = "disconnect"
    # Respostas do Servidor
    RESPONSE = "response"
    IP_RESPONSE = "ip_response"
    USERS_LIST = "users_list"

    # Fluxo P2P (Client <-> Client)
    P2P_HELLO = "p2p_hello"
    P2P_MSG = "p2p_msg"

    # Grupos e Offline
    ROOM_ACTION = "room_action"
    OFFLINE_STORE = "off_store"
    OFFLINE_MESSAGES = "offline_messages"

    # Grupos (TreeKEM)
    GROUP_CREATE = "group_create"
    GROUP_INIT = "group_init"
    GROUP_ADD_MEMBER = "group_add"
    GROUP_REMOVE_MEMBER = "group_remove"
    GROUP_UPDATE = "group_update"
    GROUP_KEY_PACKAGE = "group_key_package"
    GROUP_MSG = "group_msg"
    GROUP_LIST = "group_list"
    GROUP_INFO = "group_info"

    # Atualização de Segurança
    UPDATE_KEYS = "update_keys"

    # Ratchet (rotação de chaves via servidor)
    RATCHET_REQUEST = "ratchet_request"   # Cliente -> Servidor: pedir novo salt
    RATCHET_SALT = "ratchet_salt"         # Servidor -> Clientes: novo salt gerado

    # Ratchet P2P (directo entre clientes)
    RATCHET_CONTRIBUTION = "ratchet_contribution"


@dataclass
class Message:
    msg_type: str
    sender: str
    payload: Dict[str, Any]
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_str: str):
        try:
            data = json.loads(json_str)
            # Suportar tanto 'msg_type' como 'type' (legado)
            m_type = data.get("msg_type") or data.get("type") or "unknown"
            m_sender = data.get("sender") or "unknown"
            m_payload = data.get("payload") or data.get("data") or {}
            
            return cls(
                msg_type=m_type,
                sender=m_sender,
                payload=m_payload,
                timestamp=data.get("timestamp")
            )
        except Exception as e:
            print(f"[DEBUG] Erro ao decifrar JSON: {e} | Conteúdo: {json_str[:100]}")
            return None


def create_register_msg(username, pwd_hash, pub_key) -> Message:
    return Message(
        msg_type=MessageType.REGISTER.value,
        sender=username,
        payload={
            "password": pwd_hash,
            "public_key": pub_key
        }
    )


def create_p2p_chat_msg(sender, recipient, encrypted_content, nonce, tag) -> Message:
    return Message(
        msg_type=MessageType.P2P_MSG.value,
        sender=sender,
        payload={
            "recipient": recipient,
            "content": encrypted_content,
            "nonce": nonce,
            "tag": tag
        }
    )