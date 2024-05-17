import hashlib
import random
import sys
import libnum
import math
import os
from datetime import datetime
from Crypto.Cipher import AES

def FileToBinary(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()
    return binary_data

def BinaryToFile(binary_data, output_file_path):
    with open(output_file_path, 'wb') as file:
        file.write(binary_data)

def FileToString(file_path):
    with open(file_path, 'r') as file:
        string = file.read()
    return string

def StringToFile(string, output_file_path):
    with open(output_file_path, 'w') as file:
        file.write(string)

def ParseTupleFromString(string):
    return eval(string)

def Hash(binary):
    return hashlib.sha256(binary).hexdigest()

def Hashbit(binary):
    hash_value = hashlib.sha256(binary).hexdigest()
    byte_hash = hash_value[:32] 
    return byte_hash

def HashToBinary(hash_digest):
    hash_bytes = bytes.fromhex(hash_digest)
    return hash_bytes

def ByteToBinary(binary_data):
    return ''.join(format(byte, '08b') for byte in binary_data)

def StringToBinary(string):
    return ''.join(format(ord(char), '08b') for char in string)

def BinaryToByte(binary_string):
    byte_data = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    int_data = [int(byte, 2) for byte in byte_data]
    byte_string = bytes(int_data)
    return byte_string

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
    plainText = ByteToBinary(cipher.decrypt(cipherText))
    return plainText

def GeneratePrime(bitsize):
    prime1=libnum.generate_prime(bitsize//2)
    prime2=libnum.generate_prime(bitsize - bitsize//2)
    n=prime1*prime2
    phi=(prime1-1)*(prime2-1)
    # print ("\nPrime (p): %d. Length: %d bits, Digits: %d" % (prime1,libnum.len_in_bits(prime1), len(str(prime1))))  
    # print ("\nPrime (q): %d. Length: %d bits, Digits: %d" % (prime2,libnum.len_in_bits(prime2), len(str(prime2))))
    # print ("\nPrime (N): %d. Length: %d bits, Digits: %d" % (n,libnum.len_in_bits(n), len(str(n))))
    # print ("\nPrime (phi): %d. Length: %d bits, Digits: %d" % (phi,libnum.len_in_bits(phi), len(str(phi))))  
    return n, prime1, prime2, phi # need to return p,q to cal phi n

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
    Binarybits = DecimalToBinary(Power)
    Digit = 1
    for Bit in Binarybits:
        Digit = (Digit*Digit)%Mod
        if Bit != "0":
            Digit = (Digit*Num)%Mod
    return Digit

def GCD(a, b):
    a = int(a)
    b = int(b)
    while b != 0:
        a, b = b, a % b
    return a

def GenerateKey(bitsize):
    n, p, q, phi = GeneratePrime(bitsize)
    e1 = random.randrange(2, phi)
    while GCD(e1, phi) != 1:
        e1 = random.randrange(2, phi)
    d1 = InvModulo(e1, phi)
    public_key = (e1, n)
    private_key = (d1, n)
    return public_key, private_key

def DecimalToBinary(Decimal):
    return "{0:b}".format(int(Decimal))

def DecimalToBinarySpecifyBit(Decimal, Bit):
    return "{0:0{1}b}".format(Decimal, Bit)

def BinaryToDecimal(Binary):
    return int(Binary, 2)

def Plain_Spliting_Encrypt(Binary, n):
    Block_Size = math.floor(math.log2(n)) # calculate block size of plaintext
    result = [Binary[i:i+Block_Size] for i in range(0, len(Binary), Block_Size)] # separate into each block
    if len(result[-1]) < Block_Size: #[-1] is last bit, padding 1 and zero
        result[-1] += "1"
        while len(result[-1]) < Block_Size:
            result[-1] += "0"
    elif len(result[-1]) == Block_Size: # for the case that it's not need padding
        result.append("1"+"0"*(Block_Size-1)) # new element appends
    return result, Block_Size

def RSA_Encrypt(Message, Key, n):
    Result, Block_Size = Plain_Spliting_Encrypt(Message, n)
    Decimal_Block = [BinaryToDecimal(Binary) for Binary in Result]
    Encrpyt_Decimal_Block = [Modulo(Decimal, Key, n) for Decimal in Decimal_Block]
    # change into form of block_size + 1 bit
    Encrpyt_Binary_Block = [DecimalToBinarySpecifyBit(Decimal, Block_Size+1) for Decimal in Encrpyt_Decimal_Block]
    Cipher_Binary_Sequence = ''.join(Encrpyt_Binary_Block) #join all block
    return Cipher_Binary_Sequence

def Plain_Spliting_Decrypt(Binary, n):
    Block_Size = math.floor(math.log2(n))+1 # calculate block size of plaintext
    result = [Binary[i:i+Block_Size] for i in range(0, len(Binary), Block_Size)] # separate into each block
    return result, Block_Size

def RSA_Decrypt(Message, Key, n):
    Result, Block_Size = Plain_Spliting_Decrypt(Message, n)
    Encrpyted_Decimal_Block = [BinaryToDecimal(Binary) for Binary in Result]
    Decimal_Block = [Modulo(Decimal, Key, n) for Decimal in Encrpyted_Decimal_Block]
    Decrypt_Binary_Block = [DecimalToBinarySpecifyBit(Decimal, Block_Size-1) for Decimal in Decimal_Block]
    Binary_Sequence = ''.join(Decrypt_Binary_Block) #join all block
    Last_One_Index = Binary_Sequence.rfind("1")
    Message = Binary_Sequence[:Last_One_Index] #from 0 to (Last_One_Index-1)th bit ไม่นับตัวเอง
    return Message

def SendFile(sender, file, recipient):
    filePath = 'user'+sender+'/source/'+file
    fileBinary = FileToBinary(filePath)
    print('m: ',ByteToBinary(fileBinary)[:100],'...',sep='')
    sssk = GenerateSSSK(128)
    print('SSSK: ',ByteToBinary(sssk)[:100],'...',sep='')
    cipherText, nonce = EncryptAES(ByteToBinary(fileBinary), sssk)
    print('{m}ₛₛₛₖ:',ByteToBinary(cipherText)[:100],'...',sep='')
    print('N: ',ByteToBinary(nonce)[:100],'...',sep='')
    hashDigest = Hash(fileBinary)
    hashBinary = ByteToBinary(HashToBinary(hashDigest))
    print('{hashₛₕₐ₋₁(m)}: ',hashBinary[:100],'...',sep='')
    PR_S = ParseTupleFromString(FileToString('user'+sender+'/key/PR_'+sender+'.txt'))
    print('PR_S: ',PR_S)
    PU_R = ParseTupleFromString(FileToString('user'+recipient+'/key/PU_'+recipient+'.txt'))
    print('PU_R: ',PU_R)
    cipherHashBinary = RSA_Encrypt(hashBinary, PR_S[0], PR_S[1])
    print('{hashₛₕₐ₋₁(m)}ₚᵣₛ: ',cipherHashBinary[:100],'...',sep='')
    cipherSSSK = RSA_Encrypt(ByteToBinary(sssk), PU_R[0], PU_R[1])
    print('{SSSK}ₚᵤᵣ: ',cipherSSSK[:100],'...',sep='')
    cipherNonce = RSA_Encrypt(ByteToBinary(nonce), PU_R[0], PU_R[1])
    print('{N}ₚᵤᵣ: ',cipherNonce[:100],'...',sep='')
    PGP_message = str(ByteToBinary(cipherText))+'||'+str(cipherHashBinary)+'||'+str(cipherSSSK)+'||'+str(cipherNonce)
    timestamp = str(datetime.now().strftime('%S-%M-%H-%d-%m-%y'))
    StringToFile(PGP_message, f'user{recipient}/inbox/{sender.capitalize()}_{timestamp}.txt')

def DecryptFile(recipient):
    folder_path = f'user{recipient}/inbox'
    for file_name in os.listdir(folder_path):
        sender = file_name[0]
        file_path = os.path.join(folder_path, file_name)
        PGP_message = FileToString(file_path).split('||')
        PU_sender = ParseTupleFromString(FileToString(f'user{sender}/key/PU_{sender}.txt'))
        PR_recipient = ParseTupleFromString(FileToString(f'user{recipient}/key/PR_{recipient}.txt'))
        nonce = RSA_Decrypt(PGP_message[3], PR_recipient[0], PR_recipient[1])
        print('N: ', BinaryToByte(nonce)[:100],'...',sep='')
        sssk = BinaryToByte(RSA_Decrypt(PGP_message[2], PR_recipient[0], PR_recipient[1]))
        print('SSSK: ', BinaryToByte(sssk)[:100],'...',sep='')
        hashBinary = RSA_Decrypt(PGP_message[1], PU_sender[0], PU_sender[1])
        print('{hashₛₕₐ₋₁(m)}: ',hashBinary[:100],'...',sep='')
        fileBinary = DecryptAES(PGP_message[0], BinaryToByte(sssk), BinaryToByte(nonce))
        print('m: ', fileBinary[:100],'...',sep='')

DecryptFile('B')
