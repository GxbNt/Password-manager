# ciphers/block_ciphers.py

class SimpleSPN:
    def __init__(self, key):
        self.key = key

    def _substitute_encrypt(self, block):
        s_box = {i: (i + 1) % 256 for i in range(256)}
        return bytes([s_box[b] for b in block])

    def _substitute_decrypt(self, block):
        s_box_inv = {(i + 1) % 256: i for i in range(256)}
        return bytes([s_box_inv[b] for b in block])

    def _permute(self, block):
        return block[1:] + block[:1]

    def _permute_inv(self, block):
        return block[-1:] + block[:-1]

    def encrypt(self, data):
        encrypted = bytearray()
        for i in range(0, len(data), 8):  # Process in 8-byte blocks
            block = data[i:i+8].ljust(8, b'\x00')  # Pad with zeros if needed
            for _ in range(10):
                block = self._substitute_encrypt(block)
                block = self._permute(block)
                block = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(block)])
            encrypted.extend(block)
        return bytes(encrypted)

    def decrypt(self, data):
        decrypted = bytearray()
        for i in range(0, len(data), 8):  # Process in 8-byte blocks
            block = data[i:i+8]
            for _ in range(10):
                block = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(block)])
                block = self._permute_inv(block)
                block = self._substitute_decrypt(block)
            decrypted.extend(block)
        return bytes(decrypted).rstrip(b'\x00')


class FeistelNetwork:
    def __init__(self, key):
        self.key = key

    def _round_function(self, half_block, round_key):
        return bytes([b ^ round_key for b in half_block])

    def encrypt(self, data):
        encrypted = bytearray()
        for i in range(0, len(data), 8):  # Process in 8-byte blocks
            block = data[i:i+8].ljust(8, b'\x00')  # Pad with zeros if needed
            left, right = block[:4], block[4:]
            for i in range(16):
                round_key = self.key[i % len(self.key)]
                new_right = bytes([a ^ b for a, b in zip(left, self._round_function(right, round_key))])
                left, right = right, new_right
            encrypted.extend(left + right)
        return bytes(encrypted)

    def decrypt(self, data):
        decrypted = bytearray()
        for i in range(0, len(data), 8):  # Process in 8-byte blocks
            block = data[i:i+8]
            left, right = block[:4], block[4:]
            for i in reversed(range(16)):
                round_key = self.key[i % len(self.key)]
                new_left = bytes([a ^ b for a, b in zip(right, self._round_function(left, round_key))])
                right, left = left, new_left
            decrypted.extend(left + right)
        return bytes(decrypted).rstrip(b'\x00')