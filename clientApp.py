import hashlib
import random
from Crypto.Cipher import AES

def FileToBinary(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()
    return binary_data

def BinaryToFile(binary_data, output_file_path):
    with open(output_file_path, 'wb') as file:
        file.write(binary_data)

def Hash(binary):
    return hashlib.sha1(binary).hexdigest()

def HashToBinary(hash_digest):
    hash_bytes = bytes.fromhex(hash_digest)
    return hash_bytes

def ToBinaryString(binary_data):
    return ''.join(format(byte, '08b') for byte in binary_data)

def GenerateSSSK(bitLen):
    byteLen = bitLen // 8 
    randint = random.getrandbits(bitLen)
    key = randint.to_bytes(byteLen, byteorder='big')
    return key

def EncryptAES(plainTextBit, key):
    plainTextByte = int(plainTextBit, 2).to_bytes((len(plainTextBit) + 7) // 8, byteorder='big')
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipherText = cipher.encrypt(plainTextByte)
    return cipherText, nonce

def DecryptAES(cipherText, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plainText = ToBinaryString(cipher.decrypt(cipherText))
    return plainText
