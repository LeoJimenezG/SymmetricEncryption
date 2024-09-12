import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR


class SymmetricEncryption:
    def __init__(self):
        # Generate a random secret key for encryption
        self.secret_key: bytes = secrets.token_bytes(nbytes=32)
        # Generate a random vector for initialization
        self.initialization_vector: bytes = secrets.token_bytes(nbytes=16)

    def symmetric_encrypt_AES_CTR(self, message: bytes):
        # Set the AES (Advanced Encryption Standard) algorithm for encrypting
        symmetric_algorithm: AES = algorithms.AES(key=self.secret_key)
        # Set the CTR (Counter Mode) mode to use according to the algorithm
        algorithm_mode: CTR = modes.CTR(nonce=self.initialization_vector)

        # Create an object to cipher using the previous configurations
        cipher: Cipher = Cipher(algorithm=symmetric_algorithm, mode=algorithm_mode)
        # Generate the encryptor object
        encryptor = cipher.encryptor()

        # Encrypt the message
        encrypted_message: bytes = encryptor.update(message) + encryptor.finalize()
        # Return the encrypted message
        return encrypted_message

    def symmetric_decrypt_AES_CTR(self, message: bytes):
        # Set the AES (Advanced Encryption Standard) algorithm for encrypting
        symmetric_algorithm: AES = algorithms.AES(key=self.secret_key)
        # Set the CTR (Counter Mode) mode to use according to the algorithm
        algorithm_mode: CTR = modes.CTR(nonce=self.initialization_vector)

        # Create an object to cipher using the previous configurations
        cipher: Cipher = Cipher(algorithm=symmetric_algorithm, mode=algorithm_mode)
        # Generate the decryptor object
        decryptor = cipher.decryptor()

        # Decrypt the message
        decrypted_message: bytes = decryptor.update(message) + decryptor.finalize()
        # Return the decrypted message
        return decrypted_message
