# ciphers/stream_ciphers.py

class LFSR:
    def __init__(self, seed):
        self.state = int.from_bytes(seed[:4], byteorder='big') if isinstance(seed, bytes) else seed

    def _next_bit(self):
        feedback = (self.state ^ (self.state >> 2)) & 1
        self.state = (self.state >> 1) | (feedback << 7)
        return feedback

    def keystream(self, length):
        keystream = []
        for _ in range(length):
            byte = 0
            for _ in range(8):
                byte = (byte << 1) | self._next_bit()
            keystream.append(byte)
        return bytes(keystream)


class RC4Like:
    def __init__(self, key):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = self.j = 0

    def keystream(self, length):
        keystream = []
        for _ in range(length):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            keystream.append(self.S[(self.S[self.i] + self.S[self.j]) % 256])
        return bytes(keystream)