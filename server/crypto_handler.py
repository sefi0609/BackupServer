from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


# class for handling clients public and private keys,
# generating AES key and encrypting it to send to client,
# decrypting ciphers with AES asymmetric key
class CryptoHandler:
    def __init__(self, public_key, aes_key=None):
        self._public_key = public_key
        self._aes_key = aes_key     # asymmetric key, not the private key of the RSA public key
        self._aes_size = self._salt_size = 16

    # generate AES key, and encrypt it with the client's public key
    def get_aes_key(self):
        try:
            # 16 bytes == 128 bit
            self._aes_key = get_random_bytes(self._aes_size)
            public_key = RSA.importKey(self._public_key)
            cipher = PKCS1_OAEP.new(public_key)
            cipher_key = cipher.encrypt(self._aes_key)
            return cipher_key
        except Exception as e:
            print(f'Exception at get_aes_key: {e}')
            return None

    # cipher in bytes - decrypt ciphers with asymmetric encryption (AES-CBC)
    def decrypt(self, ciphertext):
        try:
            iv = b'\x00' * AES.block_size  # as written in maman15
            cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext
        except Exception as e:
            print(f'Error in decrypt(): {e}')

    # save to clients table in this class for safety reasons,
    # Although server_logic has access to the database
    def save_to_db(self, client_id, client_name, last_seen, db):
        salt = get_random_bytes(self._salt_size)
        try:
            db.save_to_clients(client_id, client_name, self._public_key, last_seen, self._aes_key + salt)
        except Exception as e:
            print(f"Exception at RSAHandler - update_db(): {e}")
            raise e

    # update the clients table when reconnect request is received
    def update_db(self, last_seen, client_id, db):
        salt = get_random_bytes(self._salt_size)
        try:
            db.update_aes_key(last_seen, self._aes_key + salt, client_id)
        except Exception as e:
            print(f"Exception at RSAHandler - update_db(): {e}")
            raise e
