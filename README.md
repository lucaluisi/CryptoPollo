# CryptoPollo 🐔
It doesn't make sense, but who would ever suspect a crypto chicken?

---

# Table of Contents

- [Documentation](#documentation)
    - [Features](#features)
    - [Algorithm Overview](#algorithm-overview)
        - [Constructor](#constructor)
        - [Padding](#padding)
        - [Dynamic S-Box Generation](#dynamic-s-box-generation)
        - [SubBytes](#subbytes-transformation)
        - [ShiftRow](#shiftrow-transformation)
        - [Massimo Transformation](#massimo-transformation)
        - [Block Encryption and Decryption](#block-encryption-and-decryption)
        - [Encryption Process](#encryption-process)
        - [Decryption Process](#decryption-process)
    - [Example Usage](#example-usage)
        - [Python](#python)
        - [PHP](#php)

---

# Documentation
**CryptoPollo** is a symmetric encryption library implemented in both Python and PHP. It features a custom block encryption algorithm inspired by AES and uses CBC (Cipher Block Chaining) mode. This documentation provides a detailed overview of its design, functionality, and usage, with side-by-side comparisons of the Python and PHP implementations.

## Features

- **Block Size**: 16 bytes
- **Key Size**: 16 bytes
- **Rounds**: Configurable, default is 10
- **Padding**: PKCS#7 style
- **Dynamic S-Box**: Deterministic and derived per block
- **Encryption Mode**: CBC (Cipher Block Chaining)
- **Full Support**: Encryption and decryption

---

## What Does the Algorithm Do?

The CryptoPollo algorithm performs the following steps to securely encrypt and decrypt data:

1. **Initialization Vector (IV)**:
   - An IV is generated (or provided) to ensure that encryption is unique for every operation, even with the same plaintext and key.

2. **Encryption**
    - **Padding**:<br> 
        The plaintext is padded to make its length a multiple of the block size (16 bytes). This ensures all data can be processed in fixed-size blocks.
    - **Block-by-Block Encryption**:
       - For each block of plaintext:
         1. The plaintext block is XORed with the previous ciphertext block (or the IV for the first block).
         2. A dynamic **S-Box** is derived using the key and the previous ciphertext block (or the IV for the first block).
         3. The block undergoes the following transformations:
            - **AddRoundKey**: Each byte is XORed with the corresponding byte of the key.
            - **SubBytes**: Each byte in the block is replaced using the derived S-Box.
            - **ShiftRow**: The block's rows are cyclically shifted to enhance diffusion.
            - **MassimoTransform**: Each byte is XORed with the corresponding byte of a shuffled `"massimo__carucci"` string.
         4. The resulting block becomes the next ciphertext block.

    - **Concatenate IV and Ciphertext**:<br>
        After processing all blocks, the IV is prefixed to the ciphertext to ensure the receiver has the necessary data for decryption.

3. **Decryption**:
    - **Block-by-Block Decryption**:
        - For each block of ciphertext:
            1. The IV (or the previous ciphertext block) is used to derive the dynamic **S-Box**.
            2. The block undergoes the reverse transformations:
                - **Inverse MassimoTransform**
                - **Inverse ShiftRow**
                - **Inverse SubBytes**: Each byte is replaced using the inverse S-Box.
                - **Inverse AddRoundKey**
            3. The result is XORed with the previous ciphertext block (or the IV for the first block) to retrieve the original plaintext.
    - **Remove Padding**:<br>
       After decrypting all blocks, padding is removed from the final plaintext to restore the original data.

---

## Constructor

The `CryptoPollo` class is initialized with the following parameters:
- `key`: A 16-byte encryption key.
- `iv`: A 16-byte Initialization Vector (IV).
- `num_rounds`: The number of encryption/decryption rounds (default is 10).

The constructor validates the size of the `key` and `iv` to ensure they meet the required length.


#### Python
```python
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
```

#### PHP
```php
class CryptoPollo {
    private $blockSize = 16;
    private $keySize = 16;
    private $key;
    private $iv;
    private $numRounds;

    public function __construct(string $key, string $iv, int $numRounds = 10) {
        if (strlen($key) !== $this->keySize) {
            throw new Exception("Key must be exactly {$this->keySize} bytes.");
        }
        if (strlen($iv) !== $this->blockSize) {
            throw new Exception("IV must be exactly {$this->blockSize} bytes.");
        }
        if (!is_numeric($numRounds)) {
            throw new Exception("Number of rounds must be a number.");
        }
        $this->key = $key;
        $this->iv = $iv;
        $this->numRounds = $numRounds;
        $this->massimo = array_map('ord', str_split("massimo__carucci", 1));
    }
```

---

## Padding
CryptoPollo uses **PKCS#7-style** padding to ensure the plaintext length is a multiple of the block size.

#### Python
```python
def _add_padding(self, data: bytes) -> bytes:
    padding_len = self.BLOCK_SIZE - len(data) % self.BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len
    
def _remove_padding(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]
```

#### PHP
```php
private function addPadding(string $data): string {
    $paddingLen = $this->blockSize - (strlen($data) % $this->blockSize);
    return $data . str_repeat(chr($paddingLen), $paddingLen);
}

private function removePadding(string $data): string {
    $paddingLen = ord($data[strlen($data) - 1]);
    return substr($data, 0, -$paddingLen);
}
```

---

## Dynamic S-Box Generation
The `_derive_sbox` function generates a deterministic S-Box using the SHA-256 hash of the seed (`previous_block + key`). The `_derive_inv_sbox` function computes the inverse of the S-Box.

#### Python
```python
def _derive_sbox(seed: bytes) -> list:
    hash_value = hashlib.sha256(seed).digest()
    sbox = list(range(256))
    random.seed(hash_value)
    random.shuffle(sbox)
    return sbox

def _derive_inv_sbox(sbox: list) -> list:
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox
```

#### PHP
```php
private function deriveSBox(string $seed): array {
    $hash = hash('sha256', $seed, true);
    $sbox = range(0, 255);
    mt_srand(unpack('N', $hash)[1]);
    shuffle($sbox);
    return $sbox;
}

private function deriveInvSBox(array $sbox): array {
    $invSBox = array_fill(0, 256, 0);
    foreach ($sbox as $i => $value) {
        $invSBox[$value] = $i;
    }
    return $invSBox;
}
```

---

## AddRoundKey Transformation
The **AddRoundKey** step in CryptoPollo involves XORing each byte of the block with the corresponding byte of the key. This operation contributes to diffusion and ensures that changes in the key propagate throughout the ciphertext.

#### Python
```python
def _add_round_key(self, data: bytes) -> bytes:
    return [(data[i] ^ self.key[i % len(self.key)]) for i in range(len(data))]

def _inv_add_round_key(self, data: bytes) -> bytes:
    return self._add_round_key(data) # XOR is its own inverse
```

#### PHP
```php
private function addRoundKey(array $data): array {
    return array_map(function($byte, $i) {
        return $byte ^ ord($this->key[$i % $this->keySize]);
    }, $data, array_keys($data));
}

private function invAddRoundKey(array $data): array {
    return $this->addRoundKey($data); // XOR is its own inverse
}
```

---

## SubBytes Transformation
The **SubBytes** step replaces each byte in the block with a corresponding value from a dynamically derived S-Box. This enhances non-linearity, making the ciphertext less predictable and resistant to linear cryptanalysis.

#### Python
```python
def _sub_bytes(data: list, sbox: list) -> list:
    return [sbox[byte] for byte in data]

def _inv_sub_bytes(data: list, inv_sbox: list) -> list:
    return [inv_sbox[byte] for byte in data]
```

#### PHP
```php
private function subBytes(array $data, array $sbox): array {
    return array_map(fn($byte) => $sbox[$byte], $data);
}

private function invSubBytes(array $data, array $invSBox): array {
    return array_map(fn($byte) => $invSBox[$byte], $data);
}
```

---

## ShiftRow Transformation
The **ShiftRow** step cyclically shifts the bytes in the block to different positions.

#### Python
```python
def _shift_row(data: bytes, shift_value: int) -> bytes:
    shift_value = shift_value % len(data)
    return data[shift_value:] + data[:shift_value]

def _inv_shift_row(data: bytes, shift_value: int) -> bytes:
    shift_value = shift_value % len(data)
    return data[-shift_value:] + data[:-shift_value]
```

#### PHP
```php
private function shiftRows(array $data, int $shiftValue): array {
    $shiftValue = $shiftValue % $this->blockSize;
    return array_merge(array_slice($data, $shiftValue), array_slice($data, 0, $shiftValue));
}

private function invShiftRows(array $data, int $shiftValue): array {
    $shiftValue = $shiftValue % $this->blockSize;
    return array_merge(array_slice($data, -$shiftValue), array_slice($data, 0, -$shiftValue));
}
```

---

### Massimo Transformation
The Massimo transformation is a custom transformation that uses a shuffled version of the string `"massimo__carucci"` to XOR with the state.

#### Python
```python
def _massimo_transform(self, data: bytes, round_value: int) -> bytes:
    massimo = self.massimo.copy()
    hash_value = hashlib.sha256(bytes(self.key[massimo[round_value] % self.KEY_SIZE])).digest()
    random.seed(hash_value)
    random.shuffle(massimo)

    maxor = [(data[i] ^ massimo[i % self.BLOCK_SIZE]) for i in range(self.BLOCK_SIZE)]
    return maxor

def _inv_massimo_transform(self, data: bytes, round_value: int) -> bytes:
    return self._massimo_transform(data, round_value)
```

#### PHP
```php
private function massimoTransform(array $data, int $roundValue): array {
    $massimo = $this->massimo;
    $hash = hash('sha256', $this->key[ord($massimo[$roundValue]) % $this->keySize], true);
    mt_srand(unpack('N', $hash)[1]);
    shuffle($massimo);

    $maxor = array_map(function($byte, $i) {
        return $byte ^ $massimo[$i % $this->blockSize];
    }, $data, array_keys($data));
    return $maxor;
}

private function invMassimoTransform(array $data, int $roundValue): array {
    return $this->massimoTransform($data, $roundValue);
}
```

---

## Block Encryption and Decryption

### Encryption
Processes a single block through multiple rounds of AddRoundKey, SubBytes, ShiftRow and MassimoTransform.

#### Python
```python
def _encrypt_block(self, block: bytes, sbox: list) -> bytes:
    state = block[:]
    for r in range(self.num_rounds):
        state = self._add_round_key(state)
        state = self._sub_bytes(state, sbox)
        state = self._shift_row(state, r)
        state = self._massimo_transform(state, r)
    return state
```

#### PHP
```php
private function encryptBlock(array $block, array $sbox): array {
    $state = $block;
        for ($round = 0; $round < $this->numRounds; $round++) {
            $state = $this->addRoundKey($state);
            $state = $this->subBytes($state, $sbox);
            $state = $this->shiftRows($state, $round);
            $state = $this->massimoTransform($state, $round);
        }
        return $state;
}
```

## 

### Decryption
Reverses the transformations (Inverse MassimoTransform, Inverse ShiftRows, Inverse SubBytes and Inverse AddRoundKey) for a single block.

#### Python
```python
def _decrypt_block(self, block: bytes, inv_sbox: list) -> bytes:
    state = block[:]
    for r in range(self.num_rounds-1, -1, -1):
        state = self._inv_massimo_transform(state, r)
        state = self._inv_shift_row(state, r)
        state = self._inv_sub_bytes(state, inv_sbox)
        state = self._inv_add_round_key(state)
    return state
```

#### PHP
```php
private function decryptBlock(array $block, array $invSBox): array {
    $state = $block;
    for ($round = $this->numRounds-1; $round >= 0; $round--) {
        $state = $this->invMassimoTransform($state, $round);
        $state = $this->invShiftRows($state, $round);
        $state = $this->invSubBytes($state, $invSBox);
        $state = $this->invAddRoundKey($state);
    }
    return $state;
}
```

---

## Encryption Process
The **Encryption** process begins with padding the plaintext to ensure its length is a multiple of the block size. Each plaintext block is XORed with the previous ciphertext block (or IV for the first block), transformed using SubBytes, ShiftRows, and MixColumns, and then appended to the ciphertext. The result includes the IV as a prefix to enable decryption.

#### Python
```python
def encrypt(self, pt: bytes) -> bytes:
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
```

#### PHP
```php
public function encrypt(string $plaintext): string {
    $plaintext = $this->addPadding($plaintext);
    $encryptedBlocks = [];
    $previousBlock = array_map('ord', str_split($this->iv, 1));

    foreach (str_split($plaintext, $this->blockSize) as $block) {
        $block = array_map('ord', str_split($block, 1));
        $xoredBlock = array_map(fn($byte, $prev) => $byte ^ $prev, $block, $previousBlock);
        $seed = implode('', array_map('chr', $previousBlock)) . $this->key;
        $sbox = $this->deriveSBox($seed);
        $encryptedBlock = $this->encryptBlock($xoredBlock, $sbox);
        $encryptedBlocks[] = implode('', array_map('chr', $encryptedBlock));
        $previousBlock = $encryptedBlock;
    }

    return $this->iv . implode('', $encryptedBlocks);
}
```

---

## Decryption Process
The **Decryption** process works in reverse: ciphertext blocks are processed to undo MixColumns, ShiftRows, and SubBytes transformations. Each block is then XORed with the previous ciphertext block (or IV for the first block) to retrieve the original plaintext. Padding is removed at the end to restore the data to its original form.

### Python
```python
def decrypt(self, ct: bytes) -> bytes:
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
```

### PHP
```php
public function decrypt(string $ciphertext): string {
    $iv = substr($ciphertext, 0, $this->blockSize);
    $ciphertext = substr($ciphertext, $this->blockSize);
    $decryptedData = '';
    $previousBlock = array_map('ord', str_split($iv, 1));

    foreach (str_split($ciphertext, $this->blockSize) as $block) {
        $block = array_map('ord', str_split($block, 1));
        $seed = implode('', array_map('chr', $previousBlock)) . $this->key;
        $sbox = $this->deriveSBox($seed);
        $invSBox = $this->deriveInvSBox($sbox);
        $decryptedBlock = $this->decryptBlock($block, $invSBox);
        $xoredBlock = array_map(fn($byte, $prev) => $byte ^ $prev, $decryptedBlock, $previousBlock);
        $decryptedData .= implode('', array_map('chr', $xoredBlock));
        $previousBlock = $block;
    }

    return $this->removePadding($decryptedData);
}
```

---

## Example Usage

### Python
```python
from cryptopollo import CryptoPollo
import os

key = os.urandom(CryptoPollo.KEY_SIZE)
iv = os.urandom(CryptoPollo.BLOCK_SIZE)

plaintext = "Chi sospetterebbe di un pollo crittografico 🐔?"
print("Original message:", plaintext)

cipher = CryptoPollo(key, iv)

# Encrypt the message
ciphertext = cipher.encrypt(plaintext.encode())
print("Encrypted message:", ciphertext.hex())

# Decrypt the message
decrypted_message = cipher.decrypt(ciphertext)
print("Decrypted message:", decrypted_message.decode())
```

### PHP
```php
<?php

include('cryptopollo.php');

$key = random_bytes(16);
$iv = random_bytes(16);

$plaintext = "Chi sospetterebbe di un pollo crittografico 🐔?";
echo "Plaintext: " . $plaintext . "<br><br>";

$cipher = new CryptoPollo($key, $iv);

// Encrypt the message
$ciphertext = $cipher->encrypt($plaintext);
echo "Ciphertext (hex): " . bin2hex($ciphertext) . "<br><br>";

// Decrypt the message
$decryptedMessage = $cipher->decrypt($ciphertext);
echo "Decrypted: " . $decryptedMessage . "<br>";

?>
```
