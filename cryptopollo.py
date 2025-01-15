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
        if not num_rounds.is_integer():
            raise ValueError("Number of rounds must be an integer.")
        self.key = key
        self.iv = iv
        self.num_rounds = num_rounds
        self.massimo = list("massimo__carucci".encode())

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

    def _add_round_key(self, data: bytes) -> bytes:
        """Mix data using XOR with the key."""
        return [(data[i] ^ self.key[i % len(self.key)]) for i in range(len(data))]

    def _inv_add_round_key(self, data: bytes) -> bytes:
        """Inverse mix data using XOR with the key."""
        return self._add_round_key(data) # XOR is its own inverse

    @staticmethod
    def _sub_bytes(data: list, sbox: list) -> list:
        """Apply byte substitution using the S-Box."""
        return [sbox[byte] for byte in data]

    @staticmethod
    def _inv_sub_bytes(data: list, inv_sbox: list) -> list:
        """Apply inverse byte substitution using the inverse S-Box."""
        return [inv_sbox[byte] for byte in data]

    @staticmethod
    def _shift_row(data: bytes, shift_value: int) -> bytes:
        """Perform row shifting."""
        shift_value = shift_value % len(data)
        return data[shift_value:] + data[:shift_value]

    @staticmethod
    def _inv_shift_row(data: bytes, shift_value: int) -> bytes:
        """Perform inverse row shifting."""
        shift_value = shift_value % len(data)
        return data[-shift_value:] + data[:-shift_value]
    
    def _massimo_transform(self, data: bytes, round_value: int) -> bytes:
        """Perform the Massimo transformation."""
        massimo = self.massimo.copy()
        hash_value = hashlib.sha256(bytes(self.key[massimo[round_value] % self.KEY_SIZE])).digest()
        random.seed(hash_value)
        random.shuffle(massimo)

        maxor = [(data[i] ^ massimo[i % self.BLOCK_SIZE]) for i in range(self.BLOCK_SIZE)]
        return maxor
    
    def _inv_massimo_transform(self, data: bytes, round_value: int) -> bytes:
        """Perform the inverse Massimo transformation."""
        return self._massimo_transform(data, round_value)

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
        for r in range(self.num_rounds):
            state = self._add_round_key(state)
            state = self._sub_bytes(state, sbox)
            state = self._shift_row(state, r)
            state = self._massimo_transform(state, r)
        return state

    def _decrypt_block(self, block: bytes, inv_sbox: list) -> bytes:
        """Decrypt a single block of data."""
        state = block[:]
        for r in range(self.num_rounds-1, -1, -1):
            state = self._inv_massimo_transform(state, r)
            state = self._inv_shift_row(state, r)
            state = self._inv_sub_bytes(state, inv_sbox)
            state = self._inv_add_round_key(state)
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
