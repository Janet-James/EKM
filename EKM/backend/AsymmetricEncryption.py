from Crypto import Random
from Crypto.PublicKey import RSA
import base64

class AsymmetricEncryption:
    '''
         String RSA Encryption / Decryption using PyCrypto
         PyCrypto RSA 256 key Encryption
         Written by: Praveen Josephmasilamani
    '''
    def __init__(self, message, publickey, privatekey):
        '''
            :param message: String to encrypt and decrypt
            :param publickey: Public key for encrypt message
            :param privatekey: Private key for decrypt message
        '''
        self.message = message
        self.publickey = publickey
        self.privatekey = privatekey

    def encrypt_message(self):
        encrypted_msg = self.publickey.encrypt(self.message.encode('utf-8'), 32)[0]
        encoded_encrypted_msg = base64.b64encode(encrypted_msg)
        return encoded_encrypted_msg

    def decrypt_message(self):
        decoded_encrypted_msg = base64.b64decode(self.message)
        decoded_decrypted_msg = self.privatekey.decrypt(decoded_encrypted_msg)
        return decoded_decrypted_msg

def generate_keys():
    '''
    :return: Private and Public keys
    '''
    modulus_length = 256*4
    privatekey = RSA.generate(modulus_length, Random.new().read)
    publickey = privatekey.publickey()
    return privatekey, publickey