import socket
import threading
import struct
import json
import time
import os
import sys
from typing import Optional, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ..protocol.messages import Message, MessageType
from .session_manager import SessionManager


def run_cli(self):
        print("\n=== BEM-VINDO AO SECURE P2P CHAT ===")
        print("Comandos disponíveis:")
        print("  /register <user> <pass>  - Criar nova conta")
        print("  /login <user> <pass>     - Entrar na conta")
        print("  /chat <user> <msg>       - Enviar mensagem (P2P)")
        print("  /list                    - Ver quem está online")
        print("  /exit                    - Sair do programa")
        print("===================================\n")

        while self.running:
            raw_input = input(f"[{self.username or 'Anonimo'}] > ").strip()
            if not raw_input: continue
            
            parts = raw_input.split(" ", 2)
            cmd = parts[0].lower()

            # --- REGISTAR ---
            if cmd == "/register" and len(parts) == 3:
                user, pwd = parts[1], parts[2]
                pub_key_b64 = self.session_manager.load_or_generate_identity_keys(parts[2])
                # Cria a mensagem com o formato que a Pessoa 1 pediu no servidor
                msg = Message(MessageType.REGISTER.value, user, {
                    "username": user,
                    "password": pwd,  # Idealmente devia ser o hash da password
                    "public_key": pub_key_b64
                })
                self._send_packet(self.server_socket, msg)
                print("[*] Pedido de registo enviado...")

            # --- LOGIN ---
            elif cmd == "/login" and len(parts) == 3:
                if self.username:
                    print("[!] Já tens sessão iniciada!")
                else:
                    self.login(parts[1], parts[2])
                    print("[*] A tentar iniciar sessão...")

            # --- CHAT P2P ---
            elif cmd == "/chat" and len(parts) > 2:
                if not self.username:
                    print("[!] Precisas de fazer /login primeiro.")
                    continue
                
                target, text = parts[1], parts[2]
                
                if target in self.peer_sessions:
                    payload = self.session_manager.encrypt_for_peer(target, text)
                    if payload:
                        msg = Message(MessageType.P2P_MSG.value, self.username, payload)
                        self._send_packet(self.peer_sessions[target]["socket"], msg)
                else:
                    self.pending_chats[target] = text 
                    print(f"[*] A procurar {target}...")
                    req = Message(MessageType.GET_IP.value, self.username, {"target_user": target})
                    self._send_packet(self.server_socket, req)

            # --- LISTAR ONLINE ---
            elif cmd == "/list":
                if not self.username:
                    print("[!] Precisas de fazer /login primeiro.")
                else:   
                    req = Message(MessageType.GET_USERS.value, self.username, {})
                    self._send_packet(self.server_socket, req)
            
            # --- SAIR ---
            elif cmd == "/exit":
                # Avisa o servidor que vais sair
                if self.username:
                    msg = Message(MessageType.DISCONNECT.value, self.username, {})
                    self._send_packet(self.server_socket, msg)
                self.stop()
            
            else:
                print("[!] Comando inválido ou formato incorreto.")