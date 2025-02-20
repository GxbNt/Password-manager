# core/password_manager.py
import json
import os
from ciphers.block_ciphers import SimpleSPN, FeistelNetwork
from ciphers.stream_ciphers import LFSR, RC4Like
from utils.key_derivation import derive_key

class PasswordManager:
    def __init__(self):
        self.database_file = 'passwords.json'
        self.master_key = None
        self.database = {}

        if os.path.exists(self.database_file):
            try:
                self._load_database()
            except (json.JSONDecodeError, KeyError, ValueError):
                print("Database corrupted. Resetting...")
                os.remove(self.database_file)
                self._set_master_password()
        else:
            self._set_master_password()

    def _set_master_password(self):
        master_password = input("Set master password: ")
        self.master_key = derive_key(master_password)
        self._save_database()

    def _validate_master_password(self):
        master_password = input("Enter master password: ")
        if derive_key(master_password) == self.master_key:
            return True
        print("Invalid password!")
        return False

    def _encrypt(self, data):
        # Block Ciphers
        cipher1 = SimpleSPN(self.master_key)
        encrypted = cipher1.encrypt(data.encode())
        cipher2 = FeistelNetwork(self.master_key)
        encrypted = cipher2.encrypt(encrypted)

        # Stream Ciphers
        stream1 = LFSR(self.master_key)
        keystream1 = stream1.keystream(len(encrypted))
        encrypted = bytes([a ^ b for a, b in zip(encrypted, keystream1)])

        stream2 = RC4Like(self.master_key)
        keystream2 = stream2.keystream(len(encrypted))
        encrypted = bytes([a ^ b for a, b in zip(encrypted, keystream2)])

        return encrypted

    def _decrypt(self, encrypted_data):
        # Stream Ciphers (reverse order)
        stream2 = RC4Like(self.master_key)
        keystream2 = stream2.keystream(len(encrypted_data))
        decrypted = bytes([a ^ b for a, b in zip(encrypted_data, keystream2)])

        stream1 = LFSR(self.master_key)
        keystream1 = stream1.keystream(len(decrypted))
        decrypted = bytes([a ^ b for a, b in zip(decrypted, keystream1)])

        # Block Ciphers (reverse order)
        cipher2 = FeistelNetwork(self.master_key)
        decrypted = cipher2.decrypt(decrypted)
        cipher1 = SimpleSPN(self.master_key)
        decrypted = cipher1.decrypt(decrypted)

        return decrypted.decode('utf-8')

    def _save_database(self):
        encrypted_db = {}
        for account, creds in self.database.items():
            encrypted_db[account] = {
                'username': list(creds['username']),
                'password': list(creds['password'])
            }
        data = {
            'master_key': list(self.master_key),
            'passwords': encrypted_db
        }
        with open(self.database_file, 'w') as f:
            json.dump(data, f)

    def _load_database(self):
        with open(self.database_file, 'r') as f:
            data = json.load(f)
            self.master_key = bytes(data['master_key'])
            self.database = {}
            for account, creds in data['passwords'].items():
                self.database[account] = {
                    'username': bytes(creds['username']),
                    'password': bytes(creds['password'])
                }

    def add_password(self, account, username, password):
        self.database[account] = {
            'username': self._encrypt(username),
            'password': self._encrypt(password)
        }
        self._save_database()

    def get_password(self, account):
        if account in self.database:
            return {
                'username': self._decrypt(self.database[account]['username']),
                'password': self._decrypt(self.database[account]['password'])
            }
        return None