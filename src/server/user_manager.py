import asyncio
from typing import Optional, Dict, Any, Tuple


class OnlineUserManager:
    """
    Mantém dicionário de utilizadores ativos na RAM para P2P.
    Operações de escrita usam lock; leituras são atómicas em CPython.
    """
    
    def __init__(self):
        self._online_users: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
    
    async def add_online_user(self, username: str, ip: str, port: int, socket) -> None:
        # Adiciona utilizador online
        async with self._lock:
            self._online_users[username] = {"ip": ip, "port": port, "socket": socket}
    
    async def remove_online_user(self, username: str) -> bool:
        # Remove utilizador online
        async with self._lock:
            if username in self._online_users:
                del self._online_users[username]
                return True
            return False
    
    async def get_user_address(self, username: str) -> Optional[Tuple[str, int]]:
        # Retorna (IP, porta) para P2P
        user = self._online_users.get(username)
        return (user["ip"], user["port"]) if user else None
    
    async def is_user_online(self, username: str) -> bool:
        # Verifica se utilizador está online
        return username in self._online_users
    
    async def get_user_socket(self, username: str):
        # Retorna socket do utilizador
        user = self._online_users.get(username)
        return user["socket"] if user else None
    
    async def list_online_users(self) -> list:
        # Lista todos os usernames online
        return list(self._online_users.keys())
