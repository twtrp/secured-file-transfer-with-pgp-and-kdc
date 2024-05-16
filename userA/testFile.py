import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

def Test(oldFilePath, newFilePath):
    filePath = 'source/'+oldFilePath
    fileBinary = FileToBinary(filePath)
    print('Binary Data: ',ToBinaryString(fileBinary)[:100],'...',sep='')
    hashDigest = Hash(fileBinary)
    hashBinary = HashToBinary(hashDigest)
    print('Hashed Data: ',ToBinaryString(hashBinary)[:100],'...',sep='')
    BinaryToFile(fileBinary, 'recreated/'+newFilePath)
    newFilePath = 'recreated/'+newFilePath
    newFileBinary = FileToBinary(newFilePath)
    print('Recreated Binary Data: ',ToBinaryString(newFileBinary)[:100],'...',sep='')
    newHashDigest = Hash(newFileBinary)
    newHashBinary = HashToBinary(newHashDigest)
    print('Recreated Hashed Data: ',ToBinaryString(newHashBinary)[:100],'...',sep='')

fileName = sys.argv[1]
Test(fileName, 're_'+fileName)