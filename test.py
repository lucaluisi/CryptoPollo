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