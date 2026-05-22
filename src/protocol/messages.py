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

    # Ratchet (rotação de chaves via servidor)
    RATCHET_REQUEST = "ratchet_request"   # Cliente -> Servidor: pedir novo salt
    RATCHET_SALT = "ratchet_salt"         # Servidor -> Clientes: novo salt gerado


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
        data = json.loads(json_str)
        return cls(**data)


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