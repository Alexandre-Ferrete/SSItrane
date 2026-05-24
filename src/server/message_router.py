# Routeia mensagens entre utilizadores e gere rooms de chat
# Entrega imediata a online ou guarda offline via storage

import logging
import base64
import json
from typing import Optional, List, Dict, Any
from protocol.messages import Message, MessageType

logger = logging.getLogger(__name__)

class MessageRouter:
    """
    Routes messages between users and manages group broadcasts.
    """
    
    def __init__(self, user_manager, storage):
        """Inicializa o router com user_manager e storage."""
        self.user_manager = user_manager
        self.storage = storage
    
    async def broadcast_to_room(
        self,
        group_name: str,
        sender: str,
        epoch: int,
        content: str,
        nonce: str,
        tag: str
    ) -> bool:
        """
        Broadcast de mensagem de grupo para todos os membros ativos.
        Entrega via socket se online, ou guarda em group_messages se offline.
        """
        members = self.storage.get_group_members(group_name, only_active=True)
        if not members:
            return False

        # Criar mensagem de protocolo
        msg = Message(
            msg_type=MessageType.GROUP_MSG.value,
            sender=sender,
            payload={
                "room_name": group_name,
                "epoch":     epoch,
                "content":   content,
                "nonce":     nonce,
                "tag":       tag
            }
        )

        for m in members:
            member = m["username"]
            if member == sender: continue

            handler = await self.user_manager.get_user_socket(member)
            if handler:
                try:
                    await handler.send_message(msg)
                except Exception as e:
                    logger.error(f"Falha ao entregar msg de grupo online a {member}: {e}")
                    self._store_offline_group_msg(group_name, member, sender, epoch, content, nonce, tag)
            else:
                self._store_offline_group_msg(group_name, member, sender, epoch, content, nonce, tag)
        
        return True

    def _store_offline_group_msg(self, group_name, recipient, sender, epoch, content, nonce, tag):
        """Helper para guardar mensagem de grupo na BD."""
        try:
            c_bytes = base64.b64decode(content)
            n_bytes = base64.b64decode(nonce)
            t_bytes = base64.b64decode(tag)
            self.storage.store_group_message(group_name, recipient, sender, epoch, c_bytes, n_bytes, t_bytes)
        except Exception as e:
            logger.error(f"Erro ao guardar msg de grupo offline para {recipient}: {e}")
