import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .server import main

if __name__ == '__main__':
    try:
        # Executa a função main do chat_server.py
        asyncio.run(main())
    except KeyboardInterrupt:
        # Garante que o terminal fica limpo ao sair
        sys.exit(0)