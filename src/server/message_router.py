# Routeia mensagens entre utilizadores e gere rooms de chat
# Entrega imediata a online ou guarda offline via storage
# Notifica contactos de mudanças de estado online/offline

import logging
import threading
from typing import Optional, List, Dict, Any


class MessageRouter:
    """
    Routes messages between users.
    Coordinates P2P connections via IP lookup.
    """
    
    def __init__(self, user_manager, storage):
        """Inicializa o router com user_manager e storage."""
        # self.user_manager = user_manager
        # self.storage = storage
        # self._rooms = {}  # room_name -> {members: [], created_by: str}
        # self._lock = threading.Lock()
        pass
    
    def route_message(
        self,
        sender: str,
        recipient: str,
        encrypted_content: bytes,
        message_id: str,
        ephemeral_public_key: bytes = None,
        nonce: bytes = None,
        tag: bytes = None
    ) -> Dict[str, Any]:
        """Routeia mensagem para destinatário (notifica para usar P2P)."""
        # 1. Verificar se destinatário está online
        # 2. Se online: deliver_to_online()
        # 3. Se offline: store_offline()
        # 4. Retornar status
        pass
    
    def deliver_to_online(self, recipient: str, message: Dict[str, Any]) -> bool:
        """Entrega mensagem a utilizador online."""
        # handler = user_manager.get_handler(recipient)
        # handler.send_message(message)
        # return True/False
        pass
    
    def store_offline(
        self,
        recipient: str,
        sender: str,
        encrypted_content: bytes,
        message_id: str,
        ephemeral_public_key: bytes = None,
        nonce: bytes = None,
        tag: bytes = None
    ):
        """Guarda mensagem para entrega posterior."""
        # storage.store_offline_message(...)
        pass
    
    def deliver_pending_offline_messages(self, username: str, handler):
        """Entrega mensagens offline ao utilizador no login."""
        # msgs = storage.get_offline_messages(username)
        # for msg in msgs:
        #     handler.send_message(msg)
        #     storage.mark_offline_message_delivered(msg["id"])
        pass
    
    def create_room(self, room_name: str, created_by: str) -> Dict[str, Any]:
        """Cria novo room de chat."""
        # Com lock: verificar se existe, criar entrada no dicionário
        pass
    
    def delete_room(self, room_name: str) -> bool:
        """Elimina room de chat."""
        pass
    
    def join_room(self, room_name: str, username: str) -> Dict[str, Any]:
        """Adiciona utilizador a um room."""
        pass
    
    def leave_room(self, room_name: str, username: str) -> bool:
        """Remove utilizador de um room."""
        pass
    
    def broadcast_to_room(
        self,
        room_name: str,
        sender: str,
        encrypted_content: bytes,
        message_id: str,
        ephemeral_public_key: bytes = None,
        nonce: bytes = None,
        tag: bytes = None
    ) -> Dict[str, Any]:
        """Broadcast mensagem para todos os membros do room."""
        pass
    
    def get_room_members(self, room_name: str) -> List[str]:
        """Retorna membros de um room."""
        pass
    
    def get_all_rooms(self) -> List[Dict[str, Any]]:
        """Retorna todos os rooms ativos."""
        pass
    
    def _notify_room_members(self, room_name: str, message: Dict[str, Any], exclude: List[str] = None):
        """Envia notificação a todos os membros do room."""
        pass
    
    def notify_user_online(self, username: str, handler):
        """Notifica contactos que utilizador ficou online."""
        pass
    
    def notify_user_offline(self, username: str):
        """Notifica contactos que utilizador ficou offline."""
        pass
    
    def get_room_info(self, room_name: str) -> Optional[Dict[str, Any]]:
        """Retorna informação do room."""
        pass
