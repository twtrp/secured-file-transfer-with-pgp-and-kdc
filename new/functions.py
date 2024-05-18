import hashlib
import random
import sys
import libnum
import math
import os
from datetime import datetime
from Crypto.Cipher import AES
from util import *

def GCD(a, b):
    a = int(a)
    b = int(b)
    while b != 0:
        a, b = b, a % b
    return a

def ExtEuclid(a, b):
    if b == 0:
        return (a, 1, 0)
    c1, x1, y1 = ExtEuclid(b, a % b)
    c = c1
    x = y1
    y = x1 - (a // b) * y1
    return (c, x, y)

def InvModulo(Num, Mod):
    gcd, x, y = ExtEuclid(Num, Mod)
    if gcd != 1:
        raise ValueError(f"No modular inverse exists for {Num} modulo {Mod}")
    else:
        return x % Mod

def Modulo(Num, Power, Mod):
    binary_bits = DecimalToBinary(Power)
    digit = 1
    for Bit in binary_bits:
        digit = (digit*digit)%Mod
        if Bit != "0":
            digit = (digit*Num)%Mod
    return digit

def GeneratePrimeRSA(bitsize):
    prime1=libnum.generate_prime(bitsize//2)
    prime2=libnum.generate_prime(bitsize - bitsize//2)
    n=prime1*prime2
    phi=(prime1-1)*(prime2-1)
    return n, prime1, prime2, phi

def GenerateKeyRSA(bitsize):
    n, p, q, phi = GeneratePrimeRSA(bitsize)
    e1 = random.randrange(2, phi)
    while GCD(e1, phi) != 1:
        e1 = random.randrange(2, phi)
    d1 = InvModulo(e1, phi)
    public_key = (e1, n)
    private_key = (d1, n)
    return public_key, private_key

def PlainSplitingEncrypt(binary, n):
    block_size = math.floor(math.log2(n))
    result = [binary[i:i+block_size] for i in range(0, len(binary), block_size)] 
    if len(result[-1]) < block_size:
        result[-1] += "1"
        while len(result[-1]) < block_size:
            result[-1] += "0"
    elif len(result[-1]) == block_size:
        result.append("1"+"0"*(block_size-1))
    return result, block_size

def EncryptRSA(message, key, n):
    result, block_size = PlainSplitingEncrypt(message, n)
    decimal_block = [BinaryToDecimal(binary) for binary in result]
    encrypt_decimal_block = [Modulo(Decimal, key, n) for Decimal in decimal_block]
    encrypt_binary_block = [DecimalToBinarySpecifyBit(Decimal, block_size+1) for Decimal in encrypt_decimal_block]
    cipher_binary_sequence = ''.join(encrypt_binary_block)
    return cipher_binary_sequence

def PlainSplitingDecrypt(binary, n):
    block_size = math.floor(math.log2(n))+1
    result = [binary[i:i+block_size] for i in range(0, len(binary), block_size)] 
    return result, block_size

def DecryptRSA(message, key, n):
    result, block_size = PlainSplitingDecrypt(message, n)
    encrpyted_decimal_block = [BinaryToDecimal(binary) for binary in result]
    decimal_block = [Modulo(Decimal, key, n) for Decimal in encrpyted_decimal_block]
    decrypt_binary_block = [DecimalToBinarySpecifyBit(decimal, block_size-1) for decimal in decimal_block]
    binary_sequence = ''.join(decrypt_binary_block) 
    last_one_index = binary_sequence.rfind("1")
    message = binary_sequence[:last_one_index] 
    return message

def GenerateKeySSSK(bit_len):
    byte_len = bit_len // 8 
    randint = random.getrandbits(bit_len)
    key = randint.to_bytes(byte_len, byteorder='big')
    return key

def EncryptAES(plain_text_bit, key):
    plain_text_byte = int(plain_text_bit, 2).to_bytes((len(plain_text_bit) + 7) // 8, byteorder='big')
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text = cipher.encrypt(plain_text_byte)
    return cipher_text, nonce

def DecryptAES(cipher_text, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = ByteToBinary(cipher.decrypt(cipher_text))
    return plain_text

def SendFile(sender, recipient, PR_S, n_S, PU_R, n_R):
    folder_path = f'user{sender}/outbox'
    i = 1
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        file_binary = FileToBinary(file_path)
        sssk = GenerateKeySSSK(128)
        cipher_text, nonce = EncryptAES(ByteToBinary(file_binary), sssk)
        hash_digest = Hash(file_binary)
        hash_binary = ByteToBinary(HashToByte(hash_digest))
        cipher_hash_binary = EncryptRSA(hash_binary, PR_S, n_S)
        cipher_SSSK = EncryptRSA(ByteToBinary(sssk), PU_R, n_R)
        cipher_nonce = EncryptRSA(ByteToBinary(nonce), PU_R, n_R)
        cipherName = EncryptRSA(file_name, PU_R, n_R)
        PGP_message = str(ByteToBinary(cipher_text))+'||'+str(cipher_hash_binary)+'||'+str(cipher_SSSK)+'||'+str(cipher_nonce)+'||'+str(cipherName)
        timestamp = str(datetime.now().strftime('%S-%M-%H-%d-%m-%y'))
        StringToFile(PGP_message, f'user{recipient}/inbox/{sender.capitalize()}_{i}_{timestamp}.txt')
        i += 1

def DecryptFile(recipient, PR_R, n_R, PU_S, n_S):
    folder_path = f'user{recipient}/inbox'
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        PGP_message = FileToString(file_path).split('||')
        file_name = DecryptRSA(PGP_message[4], PR_R, n_R)
        print('name: ', file_name[:100],'...',sep='')
        nonce = DecryptRSA(PGP_message[3], PR_R, n_R)
        print('N: ', nonce[:100],'...',sep='')
        sssk = DecryptRSA(PGP_message[2], PR_R, n_R)
        print('SSSK: ', sssk[:100],'...',sep='')
        hash_binary = DecryptRSA(PGP_message[1], PU_S, n_S)
        print('{hashₛₕₐ₋₁(m)}: ',hash_binary[:100],'...',sep='')
        file_binary = DecryptAES(BinaryToByte(PGP_message[0]), BinaryToByte(sssk), BinaryToByte(nonce))
        print('m: ', file_binary[:100],'...',sep='')
        hashDigest = Hash(BinaryToByte(file_binary))
        hashM = ByteToBinary(HashToByte(hashDigest))
        if hashM == hash_binary:
            BinaryToFile(BinaryToByte(file_binary),f'user{recipient}/files/{BinaryToString(file_name)}')
            os.remove(file_path)