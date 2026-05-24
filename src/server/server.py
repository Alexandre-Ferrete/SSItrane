import asyncio
import logging
import signal
import os
import sys
import traceback

from .storage import Storage
from .user_manager import OnlineUserManager
from .tcp_handler import ClientHandler
from .server_keys_generator import generate_server_keys, load_server_pubkey, load_server_privkey
from .message_router import MessageRouter

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
        self.ca_priv_key = None
        self.ca_pub_key = None
        self.keys_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    async def start(self, password: str):
        """Inicializa storage e arranca o servidor."""
        ca_identity = os.path.join(self.keys_dir, "ca_identity.key")
        ca_public   = os.path.join(self.keys_dir, "ca_public.key")

        try:
            if os.path.exists(ca_identity) and os.path.exists(ca_public):
                logger.info("[*] Chaves do servidor já existem. A carregar...")
                self.ca_priv_key = load_server_privkey(ca_identity, password)
                self.ca_pub_key  = load_server_pubkey(ca_public)
            else:
                logger.info("[*] Chaves do servidor não encontradas. A gerar novas chaves...")
                generate_server_keys(password, ca_identity, ca_public)
                self.ca_priv_key = load_server_privkey(ca_identity, password)
                self.ca_pub_key  = load_server_pubkey(ca_public)

            self.storage.initialize()
            self.router = MessageRouter(self.online_users, self.storage)
            self.server = await asyncio.start_server(
                self.handle_client, self.host, self.port
            )

            addr = self.server.sockets[0].getsockname()
            logger.info(f"[*] Servidor à escuta em {addr}")
            return True

        except Exception as e:
            logger.error(f"[!] Erro fatal no arranque do servidor: {e}")
            traceback.print_exc()
            return False

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        logger.info(f"[+] Nova conexão: {addr}")
        handler = ClientHandler(reader, writer, self)
        await handler.handle()

    async def shutdown(self):
        logger.info("[*] A encerrar servidor...")
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.storage.close()
        logger.info("[*] Recursos libertados.")


async def main():
    # Lê a password ANTES de entrar no event loop — sem bloquear asyncio
    password = os.environ.get("SERVER_PASSWORD")
    if not password:
        password = await asyncio.get_event_loop().run_in_executor(
            None, lambda: input("Defina a password para o servidor: ")
        )

    if password != "server":
        logger.error("[!] Password incorreta. Encerrando.")
        sys.exit(1)

    server = ChatServer()
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    ok = await server.start(password)
    if not ok:
        return

    # serve_forever corre como task separada; main aguarda stop_event
    serve_task = asyncio.create_task(server.server.serve_forever())

    try:
        await stop_event.wait()
    finally:
        serve_task.cancel()
        await server.shutdown()