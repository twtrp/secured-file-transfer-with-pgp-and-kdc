import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

bitsize = 128

def CreateKeyFile(owner):
    publicKey, privateKey = GenerateKey(bitsize)
    print('public:',publicKey[:100],'...',sep='')
    print('private:',privateKey[:100],'...',sep='')
    with open('user'+owner+"/key/PU_"+owner+".txt", 'w') as file:
        file.write(str(publicKey))
    with open('user'+owner+"/key/PR_"+owner+".txt", 'w') as file:
        file.write(str(privateKey))

owner = sys.argv[1]
CreateKeyFile(owner)