import beefish
import os

class SymmetricEncryption:
    '''
     File Encryption / Decryption using beefish
     Blowfish key Encryption
     Written by: Praveen Josephmasilamani
    '''
    def __init__(self,key,filename,path):
        '''
            :parm: key: secret password, filename: encrypt file
            :return: boolean return true and fasle
        '''
        self.key = key
        self.filename = filename
        self.e_outFile = os.path.join(os.path.dirname(path),os.path.basename(self.filename)+'.enc')
        self.d_outFile = os.path.join(os.path.dirname(path),os.path.basename(self.filename[:-4]))

    def encrypt(self):
        try:
            beefish.encrypt_file(self.filename,self.e_outFile,self.key)
            return True
        except Exception as e:
            print(e)
            return False

    def decrypt(self):
        try:
            beefish.decrypt_file(self.filename,self.d_outFile,self.key)
            return True
        except Exception as e:
            print(e)
            return False