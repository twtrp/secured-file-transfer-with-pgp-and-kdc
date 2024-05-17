import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

m = '1010011000111100'
print('Original:',m)

sssk = GenerateSSSK(128)
print('SSSK:',sssk)
cipherText, nonce = EncryptAES(m, sssk)
print('Ciphertext:',cipherText)
plainText = DecryptAES(cipherText, sssk, nonce)
print('Decrypted:',plainText)