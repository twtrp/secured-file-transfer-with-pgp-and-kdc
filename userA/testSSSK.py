import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

m = '10101010'
print('Original:',m)

sssk = GenerateSSSK(128)
print('SSSK:',sssk)
cipherText = EncryptAES(m, sssk)
print('Ciphertext:',cipherText)
plainText = DecryptAES(cipherText, sssk)
print('Decrypted:',plainText)