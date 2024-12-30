import random
import hashlib

class CryptoPollo:
    BLOCK_SIZE = 16
    KEY_SIZE = 16

    def __init__(self, key: bytes, iv: bytes, num_rounds: int = 10):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be exactly {self.KEY_SIZE} bytes.")
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV must be exactly {self.BLOCK_SIZE} bytes.")
        self.key = key
        self.iv = iv
        self.num_rounds = num_rounds

    @staticmethod
    def _derive_sbox(seed: bytes) -> list:
        """Generate a deterministic S-Box based on the seed."""
        hash_value = hashlib.sha256(seed).digest()
        sbox = list(range(256))
        random.seed(hash_value)
        random.shuffle(sbox)
        return sbox

    @staticmethod
    def _derive_inv_sbox(sbox: list) -> list:
        """Generate the inverse S-Box."""
        inv_sbox = [0] * 256
        for i in range(256):
            inv_sbox[sbox[i]] = i
        return inv_sbox

    @staticmethod
    def _sub_bytes(data: list, sbox: list) -> list:
        """Apply byte substitution using the S-Box."""
        return [sbox[byte] for byte in data]

    @staticmethod
    def _inv_sub_bytes(data: list, inv_sbox: list) -> list:
        """Apply inverse byte substitution using the inverse S-Box."""
        return [inv_sbox[byte] for byte in data]

    @staticmethod
    def _shift_rows(data: bytes) -> bytes:
        """Perform row shifting."""
        return data[1:] + data[:1]

    @staticmethod
    def _inv_shift_rows(data: bytes) -> bytes:
        """Perform inverse row shifting."""
        return data[-1:] + data[:-1]

    def _mix_columns(self, data: bytes) -> bytes:
        """Mix data using XOR with the key."""
        return [(data[i] ^ self.key[i % len(self.key)]) for i in range(len(data))]

    def _inv_mix_columns(self, data: bytes) -> bytes:
        """Inverse mix data using XOR with the key."""
        return self._mix_columns(data) # XOR is its own inverse

    def _add_padding(self, data: bytes) -> bytes:
        """Add padding to make data a multiple of BLOCK_SIZE."""
        padding_len = self.BLOCK_SIZE - len(data) % self.BLOCK_SIZE
        return data + bytes([padding_len]) * padding_len

    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        """Remove padding from the data."""
        padding_len = data[-1]
        return data[:-padding_len]

    def _encrypt_block(self, block: bytes, sbox: list) -> bytes:
        """Encrypt a single block of data."""
        state = block[:]
        for _ in range(self.num_rounds):
            state = self._sub_bytes(state, sbox)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
        return state

    def _decrypt_block(self, block: bytes, inv_sbox: list) -> bytes:
        """Decrypt a single block of data."""
        state = block[:]
        for _ in range(self.num_rounds):
            state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state, inv_sbox)
        return state

    def encrypt(self, pt: bytes) -> bytes:
        """Encrypt data in CBC mode."""
        pt = self._add_padding(pt)
        encrypted_blocks = []
        previous_block = self.iv

        for i in range(0, len(pt), self.BLOCK_SIZE):
            block = pt[i:i + self.BLOCK_SIZE]
            xored_block = [block[j] ^ previous_block[j] for j in range(self.BLOCK_SIZE)]
            seed = bytes(previous_block) + self.key  # Seed for the S-Box
            sbox = self._derive_sbox(seed)
            encrypted_block = self._encrypt_block(xored_block, sbox)
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_block

        return self.iv + b''.join(bytes(b) for b in encrypted_blocks)

    def decrypt(self, ct: bytes) -> bytes:
        """Decrypt data in CBC mode."""
        decrypted_data = b""
        previous_block = ct[:self.BLOCK_SIZE]
        ct = ct[self.BLOCK_SIZE:]

        for i in range(0, len(ct), self.BLOCK_SIZE):
            block = ct[i:i + self.BLOCK_SIZE]
            seed = bytes(previous_block) + self.key  # Seed for the S-Box
            sbox = self._derive_sbox(seed)
            inv_sbox = self._derive_inv_sbox(sbox)
            decrypted_block = self._decrypt_block(block, inv_sbox)
            xored_block = [decrypted_block[j] ^ previous_block[j] for j in range(self.BLOCK_SIZE)]
            decrypted_data += bytes(xored_block)
            previous_block = block

        return self._remove_padding(decrypted_data)
