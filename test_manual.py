#!/usr/bin/env python3
"""
Interactive Test Script - Simulates real user manual testing
Based on test_guide.txt - mimics what a user would type manually
"""

import socket
import threading
import time
import json
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.server.server import ChatServer
from src.client.client import ChatClient
from src.client.cli import CLI
from src.utils.helpers import encode_base64, decode_base64, generate_message_id


class ManualTestClient:
    """Simulates a real user manually typing commands"""
    
    def __init__(self, name, port=5555):
        self.name = name
        self.port = port
        self.client = None
        self.connected = False
        self.authenticated = False
        self.current_room = None
        self.received_messages = []
        
    def start(self, host='localhost'):
        """Start the client and connect to server"""
        print(f"\n[{self.name}] Starting client...")
        self.client = ChatClient(host=host, port=self.port)
        self.connected = self.client.connect()
        if self.connected:
            print(f"[{self.name}] Connected to server")
            # Override message handler to capture incoming messages
            self.client._process_message = self._capture_message
        return self.connected
    
    def _capture_message(self, data):
        """Capture incoming messages"""
        try:
            msg = json.loads(data.decode('utf-8'))
            self.received_messages.append(msg)
            print(f"[{self.name}] Received: {msg.get('type', 'unknown')}")
        except:
            pass
    
    def type_command(self, command):
        """Simulate user typing a command"""
        print(f"\n[{self.name}] > {command}")
        
        # Parse and execute command
        parts = command.split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd == "register":
            return self._register(args)
        elif cmd == "login":
            return self._login(args)
        elif cmd == "msg":
            return self._send_message(args)
        elif cmd == "users":
            return self._get_users()
        elif cmd == "rooms":
            return self._get_rooms()
        elif cmd == "create_room":
            return self._create_room(args)
        elif cmd == "join":
            return self._join_room(args)
        elif cmd == "leave":
            return self._leave_room(args)
        elif cmd == "logout":
            return self._logout()
        elif cmd == "exit":
            return self._exit()
        elif cmd == "getkey":
            return self._get_public_key(args)
        else:
            # Direct message when in room
            if self.current_room:
                return self._send_room_message(command)
            print(f"[{self.name}] Unknown command: {cmd}")
            return False
    
    def _register(self, args):
        """Register command"""
        if len(args) < 2:
            print("[ERROR] Usage: register <username> <password>")
            return False
        
        username, password = args[0], args[1]
        
        # Generate keys
        self.client.session_manager.generate_keypair()
        pub_key = self.client.session_manager.get_public_key_b64()
        
        self.client.send_message({
            "type": "register",
            "username": username,
            "password": password,
            "public_key": pub_key
        })
        
        time.sleep(0.5)
        
        # Check response
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "register_response":
                if msg.get("success"):
                    print(f"[OK] Registration successful!")
                    self.client.username = username
                    self.client.authenticated = True
                    self.client.session_manager.set_username(username)
                    # Load keys
                    self.client.session_manager.load_keys()
                    return True
                else:
                    print(f"[ERROR] {msg.get('message', 'Registration failed')}")
                    return False
        return False
    
    def _login(self, args):
        """Login command"""
        if len(args) < 2:
            print("[ERROR] Usage: login <username> <password>")
            return False
        
        username, password = args[0], args[1]
        
        # Load keys if exist
        self.client.session_manager.set_username(username)
        self.client.session_manager.load_keys()
        
        self.client.send_message({
            "type": "auth",
            "username": username,
            "password": password
        })
        
        time.sleep(0.5)
        
        # Check response
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "auth_response":
                if msg.get("success"):
                    print(f"[OK] Login successful!")
                    self.client.username = username
                    self.client.authenticated = True
                    return True
                else:
                    print(f"[ERROR] Invalid credentials")
                    return False
        return False
    
    def _send_message(self, args):
        """Send private message"""
        if len(args) < 2:
            print("[ERROR] Usage: msg <username> <message>")
            return False
        
        recipient = args[0]
        message = " ".join(args[1:])
        
        # Get recipient's public key
        recipient_key = self.client.session_manager.get_recipient_key(recipient)
        if not recipient_key:
            # Try to get from server
            self.client.send_message({
                "type": "get_public_key",
                "username": recipient
            })
            time.sleep(0.5)
            recipient_key = self.client.session_manager.get_recipient_key(recipient)
            
            if not recipient_key:
                print(f"[ERROR] No public key for {recipient}")
                return False
        
        # Encrypt and send
        encrypted = self.client.session_manager.encrypt_message(recipient, message.encode())
        
        self.client.send_message({
            "type": "chat",
            "recipient": recipient,
            "encrypted_content": encrypted["encrypted_content"],
            "encrypted_key": encrypted["encrypted_key"],
            "nonce": encrypted["nonce"],
            "tag": encrypted["tag"],
            "message_id": generate_message_id()
        })
        
        time.sleep(0.5)
        print("[STATUS] Message sent")
        return True
    
    def _get_users(self):
        """Get online users"""
        self.client.send_message({"type": "get_users"})
        time.sleep(0.5)
        
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "users_list":
                users = msg.get("users", [])
                print(f"Online users ({len(users)}): {', '.join(users)}")
                return True
        return False
    
    def _get_rooms(self):
        """Get rooms list"""
        self.client.send_message({"type": "get_rooms"})
        time.sleep(0.5)
        
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "rooms_list":
                rooms = msg.get("rooms", [])
                print(f"Available rooms ({len(rooms)}):")
                for room in rooms:
                    print(f"  - {room.get('name', 'unknown')}")
                return True
        return False
    
    def _create_room(self, args):
        """Create room"""
        if not args:
            print("[ERROR] Usage: create_room <name>")
            return False
        
        room_name = args[0]
        
        self.client.send_message({
            "type": "create_room",
            "room_name": room_name
        })
        
        time.sleep(0.5)
        
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "room_created":
                if msg.get("success"):
                    self.current_room = room_name
                    members = msg.get("members", [])
                    self.client.current_room = room_name
                    self.client._room_members[room_name] = members
                    print(f"[OK] Room '{room_name}' created")
                    return True
                else:
                    print(f"[ERROR] {msg.get('error', 'Failed to create room')}")
                    return False
        return False
    
    def _join_room(self, args):
        """Join room"""
        if not args:
            print("[ERROR] Usage: join <room_name>")
            return False
        
        room_name = args[0]
        
        self.client.send_message({
            "type": "join_room",
            "room_name": room_name
        })
        
        time.sleep(0.5)
        
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "room_joined":
                if msg.get("success"):
                    self.current_room = room_name
                    members = msg.get("members", [])
                    self.client.current_room = room_name
                    self.client._room_members[room_name] = members
                    print(f"[OK] Joined room '{room_name}'")
                    print(f"Members: {', '.join(members)}")
                    return True
                else:
                    print(f"[ERROR] {msg.get('error', 'Failed to join room')}")
                    return False
        return False
    
    def _leave_room(self, args):
        """Leave room"""
        if not args:
            print("[ERROR] Usage: leave <room_name>")
            return False
        
        room_name = args[0]
        
        self.client.send_message({
            "type": "leave_room",
            "room_name": room_name
        })
        
        time.sleep(0.5)
        
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "room_left":
                if msg.get("success"):
                    self.current_room = None
                    self.client.current_room = None
                    print(f"[OK] Left room '{room_name}'")
                    return True
                else:
                    print(f"[ERROR] {msg.get('error', 'Failed to leave room')}")
                    return False
        return False
    
    def _send_room_message(self, message):
        """Send message to current room"""
        if not self.current_room:
            print("[ERROR] Not in a room")
            return False
        
        # Get room members
        members = self.client._room_members.get(self.current_room, [])
        
        if not members:
            print("[ERROR] No members in room")
            return False
        
        # Find recipient (not self) with key
        recipient = None
        for m in members:
            if m != self.name and self.client.session_manager.get_recipient_key(m):
                recipient = m
                break
        
        if not recipient:
            # Use first available
            for m in members:
                if m != self.name:
                    recipient = m
                    break
        
        if not recipient:
            print("[ERROR] No recipient with key found")
            return False
        
        # Encrypt for recipient
        encrypted = self.client.session_manager.encrypt_message(recipient, message.encode())
        
        self.client.send_message({
            "type": "room_message",
            "room_name": self.current_room,
            "encrypted_content": encrypted["encrypted_content"],
            "encrypted_key": encrypted["encrypted_key"],
            "nonce": encrypted["nonce"],
            "tag": encrypted["tag"],
            "message_id": generate_message_id()
        })
        
        time.sleep(0.5)
        print(f"[Message sent to {self.current_room}]")
        return True
    
    def _logout(self):
        """Logout"""
        if self.client:
            self.client.send_message({"type": "disconnect"})
            time.sleep(0.3)
            self.authenticated = False
            print("[OK] Logged out successfully")
        return True
    
    def _exit(self):
        """Exit"""
        if self.client:
            self.client.disconnect()
        return True
    
    def _get_public_key(self, args):
        """Get public key of a user"""
        if not args:
            print("[ERROR] Usage: getkey <username>")
            return False
        
        username = args[0]
        
        self.client.send_message({
            "type": "get_public_key",
            "username": username
        })
        
        # Wait and process responses
        time.sleep(0.5)
        
        # Manually process responses
        for msg in self.received_messages[-3:]:
            if msg.get("type") == "public_key_response" and msg.get("username") == username:
                pub_key = decode_base64(msg.get("public_key"))
                self.client.session_manager.add_recipient_key(username, pub_key)
                print(f"[OK] Public key for {username} received")
                return True
            elif msg.get("type") == "error":
                print(f"[ERROR] {msg.get('message', 'Failed to get key')}")
                return False
        
        print(f"[STATUS] Fetching public key for {username}...")
        return True
    
    def wait_for_messages(self, timeout=2):
        """Wait for messages to arrive"""
        time.sleep(timeout)
    
    def disconnect(self):
        """Disconnect"""
        if self.client:
            self.client.disconnect()


def run_test_guide():
    """Run all tests from test_guide.txt"""
    
    print("="*60)
    print("E2EE CHAT SYSTEM - MANUAL TEST SIMULATION")
    print("Based on test_guide.txt")
    print("="*60)
    
    # Setup
    import subprocess
    
    # Kill any existing processes on port 5555
    try:
        result = subprocess.run(['lsof', '-ti', ':5555'], capture_output=True, text=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                try:
                    os.kill(int(pid), 9)
                except:
                    pass
            time.sleep(1)
    except:
        pass
    
    # Clean up old data
    if os.path.exists("data/server.db"):
        os.remove("data/server.db")
    
    # Start server
    print("\n[Setting up server...]")
    server = ChatServer(host='127.0.0.1', port=5555)
    server.start()
    time.sleep(1)
    print("[Server started on 127.0.0.1:5555]")
    
    try:
        # ==============================================
        # TEST 1: Registration
        # ==============================================
        print("\n" + "="*50)
        print("TEST 1: REGISTRATION")
        print("="*50)
        
        alice = ManualTestClient("Alice", 5555)
        alice.start()
        
        print("\n--- Alice registers ---")
        alice.type_command("register alice password123")
        
        bob = ManualTestClient("Bob", 5555)
        bob.start()
        
        print("\n--- Bob registers ---")
        bob.type_command("register bob secure456")
        
        # Invalid registrations
        print("\n--- Invalid: short username ---")
        alice.type_command("register ab password123")
        
        print("\n--- Invalid: short password ---")
        alice.type_command("register testuser password")
        
        print("\n--- Invalid: duplicate username ---")
        alice.type_command("register alice abc12345")
        
        # ==============================================
        # TEST 2: Login
        # ==============================================
        print("\n" + "="*50)
        print("TEST 2: LOGIN")
        print("="*50)
        
        alice.disconnect()
        alice = ManualTestClient("Alice", 5555)
        alice.start()
        
        print("\n--- Alice login ---")
        alice.type_command("login alice password123")
        
        # Bob already logged in from registration
        
        # Failed login
        print("\n--- Failed: wrong password ---")
        alice.type_command("login alice wrongpassword")
        
        print("\n--- Failed: non-existent user ---")
        alice.type_command("login nonexistent pass1234")
        
        # ==============================================
        # TEST 3: Private Messaging
        # ==============================================
        print("\n" + "="*50)
        print("TEST 3: PRIVATE MESSAGING")
        print("="*50)
        
        print("\n--- Alice gets users ---")
        alice.type_command("users")
        
        print("\n--- Alice gets Bob's key ---")
        alice.type_command("getkey bob")
        
        print("\n--- Bob gets Alice's key ---")
        bob.type_command("getkey alice")
        
        time.sleep(1)
        
        print("\n--- Alice sends message to Bob ---")
        alice.type_command("msg bob Hello Bob! This is encrypted.")
        
        bob.wait_for_messages(2)
        
        # Check if Bob got message
        print("\n--- Bob checking for messages ---")
        
        # ==============================================
        # TEST 4: Offline Messages
        # ==============================================
        print("\n" + "="*50)
        print("TEST 4: OFFLINE MESSAGES")
        print("="*50)
        
        print("\n--- Bob logs out ---")
        bob.type_command("logout")
        
        print("\n--- Alice sends to offline Bob ---")
        alice.type_command("msg bob Hello Bob, are you there?")
        
        print("\n--- Bob logs back in ---")
        bob = ManualTestClient("Bob", 5555)
        bob.start()
        bob.type_command("login bob secure456")
        
        time.sleep(1)
        
        # ==============================================
        # TEST 5: Group Chat (Rooms)
        # ==============================================
        print("\n" + "="*50)
        print("TEST 5: GROUP CHAT (ROOMS)")
        print("="*50)
        
        print("\n--- Alice creates room ---")
        alice.type_command("create_room security")
        
        print("\n--- Alice gets rooms ---")
        alice.type_command("rooms")
        
        print("\n--- Alice joins room ---")
        alice.type_command("join security")
        
        print("\n--- Bob gets rooms ---")
        bob.type_command("rooms")
        
        print("\n--- Bob joins room ---")
        bob.type_command("join security")
        
        time.sleep(1)
        
        # Alice needs Bob's key for room messages
        print("\n--- Alice gets Bob's key for room ---")
        alice.type_command("getkey bob")
        
        print("\n--- Alice sends to room (type directly) ---")
        alice._send_room_message("Hello everyone in security room!")
        
        print("\n--- Bob gets Alice's key for room ---")
        bob.type_command("getkey alice")
        
        time.sleep(1)
        
        print("\n--- Bob sends to room ---")
        bob._send_room_message("Hello Alice!")
        
        print("\n--- Alice leaves room ---")
        alice.type_command("leave security")
        
        # ==============================================
        # TEST 6: User Status Notifications
        # ==============================================
        print("\n" + "="*50)
        print("TEST 6: USER STATUS NOTIFICATIONS")
        print("="*50)
        
        print("\n--- Charlie joins ---")
        charlie = ManualTestClient("Charlie", 5555)
        charlie.start()
        charlie.type_command("register charlie pass1234")
        charlie.type_command("login charlie pass1234")
        
        time.sleep(1)
        
        print("\n--- Charlie logs out ---")
        charlie.type_command("logout")
        
        # ==============================================
        # TEST 9: Error Handling
        # ==============================================
        print("\n" + "="*50)
        print("TEST 9: ERROR HANDLING")
        print("="*50)
        
        print("\n--- Try to msg non-existent user ---")
        alice.type_command("msg invaliduser Hello")
        
        print("\n--- Try to create existing room ---")
        alice.type_command("create_room security")
        
        print("\n--- Try to send to yourself ---")
        alice.type_command("msg alice Hello myself")
        
        # ==============================================
        # TEST 10: Exit Cleanly
        # ==============================================
        print("\n" + "="*50)
        print("TEST 10: EXIT CLEANLY")
        print("="*50)
        
        print("\n--- Alice exits ---")
        alice.type_command("logout")
        alice.disconnect()
        
        print("\n--- Bob exits ---")
        bob.disconnect()
        
        print("\n--- Charlie exits ---")
        charlie.disconnect()
        
        print("\n--- Server shutdown ---")
        
    finally:
        server.shutdown()
        print("\n[Server shutdown complete]")
    
    print("\n" + "="*50)
    print("TEST SIMULATION COMPLETE")
    print("="*50)


if __name__ == "__main__":
    run_test_guide()