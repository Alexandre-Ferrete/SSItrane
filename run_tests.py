#!/usr/bin/env python3
"""
Simple Test Script for E2EE Chat System
Tests core functionality without complex networking
"""

import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.server.storage import Storage
from src.server.message_router import MessageRouter
from src.server.user_manager import UserManager
from src.crypto.asymmetric import generate_keypair
from src.crypto.hybrid import encrypt, decrypt
from src.utils.helpers import encode_base64, decode_base64


class SimpleTest:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tmpdir = None
    
    def test(self, name, condition, expected=None, got=None):
        if condition:
            print(f"  ✓ PASS: {name}")
            self.passed += 1
        else:
            print(f"  ✗ FAIL: {name}")
            if expected and got:
                print(f"      Expected: {expected}")
                print(f"      Got: {got}")
            self.failed += 1
    
    def run(self):
        print("\n" + "="*50)
        print("E2EE CHAT SYSTEM - CORE TESTS")
        print("="*50)
        
        # Create temp directory for test data
        self.tmpdir = tempfile.mkdtemp()
        
        try:
            self._test_storage()
            self._test_user_manager()
            self._test_crypto()
            self._test_rooms()
            
        finally:
            # Cleanup
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        
        # Summary
        print("\n" + "="*50)
        print(f"SUMMARY: {self.passed} passed, {self.failed} failed")
        print("="*50)
        
        return self.failed == 0
    
    def _test_storage(self):
        print("\n--- Storage Tests ---")
        
        storage = Storage(data_dir=self.tmpdir)
        storage.initialize()
        
        # Test user storage (save_user returns None, so just call it)
        try:
            storage.save_user("alice", {
                "password_hash": "hash123",
                "password_salt": "salt123",
                "public_key": b"pubkey",
                "certificate": b"cert",
                "registered_at": "2026-01-01",
                "banned": False
            })
            self.test("Save user", True)  # No exception means success
        except Exception as e:
            self.test("Save user", False, "no exception", str(e))
        
        # Test get user
        user = storage.get_user("alice")
        self.test("Get user", user is not None and user["username"] == "alice")
        
        # Test room storage
        result = storage.create_room("testroom", "alice")
        self.test("Create room", result == True)
        
        # Test room exists
        exists = storage.room_exists("testroom")
        self.test("Room exists", exists == True)
        
        # Test add room member
        result = storage.add_room_member("testroom", "bob")
        self.test("Add room member", result == True)
        
        # Test get room members
        members = storage.get_room_members("testroom")
        self.test("Get room members", "alice" in members and "bob" in members)
        
        # Test offline message (correct parameter order)
        storage.store_offline_message(
            recipient="bob",
            sender="alice",
            encrypted_content=b"content",
            message_id="msg1",
            ephemeral_public_key=b"key",
            nonce=b"nonce",
            tag=b"tag"
        )
        msgs = storage.get_offline_messages("bob")
        self.test("Offline message storage", len(msgs) == 1)
        
        storage.close()
    
    def _test_user_manager(self):
        print("\n--- User Manager Tests ---")
        
        storage = Storage(data_dir=self.tmpdir + "_um")
        storage.initialize()
        
        user_manager = UserManager(storage)
        
        # Test registration
        pub_key = generate_keypair()[1]
        result = user_manager.register_user("alice", "password123", pub_key)
        self.test("Register user", result["success"] == True)
        
        # Test duplicate registration
        result = user_manager.register_user("alice", "password123", pub_key)
        self.test("Duplicate registration", result["success"] == False)
        
        # Test invalid username
        result = user_manager.register_user("ab", "password123", pub_key)
        self.test("Invalid username", result["success"] == False)
        
        # Test invalid password
        result = user_manager.register_user("testuser", "short", pub_key)
        self.test("Invalid password", result["success"] == False)
        
        # Test authentication
        auth = user_manager.authenticate("alice", "password123")
        self.test("Authenticate", auth is not None)
        
        # Test failed authentication
        auth = user_manager.authenticate("alice", "wrongpass")
        self.test("Failed auth", auth is None)
        
        # Test user exists
        exists = user_manager.user_exists("alice")
        self.test("User exists", exists == True)
        
        storage.close()
    
    def _test_crypto(self):
        print("\n--- Cryptography Tests ---")
        
        # Generate keypairs
        alice_priv, alice_pub = generate_keypair()
        bob_priv, bob_pub = generate_keypair()
        
        # Test RSA hybrid encryption
        message = b"Hello, secure world!"
        enc_key, nonce, tag, ciphertext = encrypt(alice_pub, message)
        
        # Decrypt
        decrypted = decrypt(alice_priv, enc_key, nonce, tag, ciphertext)
        self.test("RSA hybrid encrypt/decrypt", decrypted == message)
        
        # Test encryption with wrong key fails
        try:
            decrypt(bob_priv, enc_key, nonce, tag, ciphertext)
            self.test("Wrong key fails", False)
        except:
            self.test("Wrong key fails", True)
        
        # Test base64 encoding
        encoded = encode_base64(b"test")
        decoded = decode_base64(encoded)
        self.test("Base64 encoding", decoded == b"test")
    
    def _test_rooms(self):
        print("\n--- Room Tests ---")
        
        storage = Storage(data_dir=self.tmpdir + "_room")
        storage.initialize()
        
        class MockUserManager:
            def __init__(self):
                self.online = {}
            def is_online(self, user):
                return user in self.online
            def get_handler(self, user):
                return None
        
        user_manager = MockUserManager()
        router = MessageRouter(user_manager, storage)
        
        # Test create room
        result = router.create_room("security", "alice")
        self.test("Create room", result["success"] == True)
        
        # Test duplicate room
        result = router.create_room("security", "alice")
        self.test("Duplicate room", result["success"] == False)
        
        # Test join room
        result = router.join_room("security", "bob")
        self.test("Join room", result["success"] == True)
        
        # Test get members
        members = router.get_room_members("security")
        self.test("Room members", "alice" in members and "bob" in members)
        
        # Test leave room
        result = router.leave_room("security", "bob")
        self.test("Leave room", result == True)
        
        storage.close()


def main():
    test = SimpleTest()
    success = test.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()