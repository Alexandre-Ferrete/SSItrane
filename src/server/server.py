import asyncio
import logging
import signal
import os
import sys

from .storage import Storage
from .user_manager import OnlineUserManager
from .tcp_handler import ClientHandler
from .server_keys_generator import generate_server_keys, load_server_pubkey, load_server_privkey

log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "server.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ChatServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 5555):
        self.host = host
        self.port = port
        self.storage = Storage()
        self.online_users = OnlineUserManager()
        self.server = None
        self.keys_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    async def start(self):
        import os
        password = os.environ.get("SERVER_PASSWORD") or input("Defina a password para o servidor: ")
        if password != "server":
            print("[!] Password incorreta. Encerrando.")
            sys.exit(1)
        """Inicializa storage e arranca o servidor."""
        ca_identity = os.path.join(self.keys_dir, "ca_identity.key")
        ca_public = os.path.join(self.keys_dir, "ca_public.key")
        if os.path.exists(ca_identity) and os.path.exists(ca_public):
            logger.info("[*] Chaves do servidor já existem. A carregar...")
            self.ca_priv_key = load_server_privkey(ca_identity, password)
            self.ca_pub_key = load_server_pubkey(ca_public)
        else:
            logger.info("[*] Chaves do servidor não encontradas. A gerar novas chaves...")
            generate_server_keys(password, ca_identity, ca_public)
            self.ca_priv_key = load_server_privkey(ca_identity, password)
            self.ca_pub_key = load_server_pubkey(ca_public)

        self.storage.initialize()
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        
        addr = self.server.sockets[0].getsockname()
        logger.info(f"[*] Servidor à escuta em {addr}")

        async with self.server:
            await self.server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Gere a ligação de cada cliente."""
        addr = writer.get_extra_info('peername')
        logger.info(f"[+] Nova conexão: {addr}")
        handler = ClientHandler(reader, writer, self)
        await handler.handle()

    async def shutdown(self):
        """Encerramento limpo com proteção contra race conditions."""
        logger.info("[*] A encerrar servidor...")
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        self.storage.close()
        logger.info("[*] Recursos libertados.")

async def main():
    """Lógica principal de execução do servidor."""
    server = ChatServer()
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    server_task = asyncio.create_task(server.start())
    
    await stop_event.wait()
    
    await server.shutdown()
    server_task.cancel()