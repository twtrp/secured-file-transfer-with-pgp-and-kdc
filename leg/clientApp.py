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
        
def StringToTuple(string):
    return eval(string)

def Hash(binary):
    return hashlib.sha256(binary).hexdigest()

def Hashbit(binary):
    hash_value = hashlib.sha256(binary).hexdigest()
    byte_hash = hash_value[:32] 
    return byte_hash

def HashToByte(hash_digest):
    hash_bytes = bytes.fromhex(hash_digest)
    return hash_bytes

def ByteToBinary(binary_data):
    return ''.join(format(byte, '08b') for byte in binary_data)

def BinaryToByte(binary_string):
    byte_data = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    int_data = [int(byte, 2) for byte in byte_data]
    byte_string = bytes(int_data)
    return byte_string

def StringToBinary(string):
    return ''.join(format(ord(char), '08b') for char in string)

def BinaryToString(binary):
    if len(binary) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")
    if any(char not in '01' for char in binary):
        raise ValueError("Binary string must contain only '0' or '1'")
    bytes = [binary[i:i+8] for i in range(0, len(binary), 8)]
    text = "".join([chr(int(byte, 2)) for byte in bytes])
    return text

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

def SendFile(sender, recipient, PR_S, PU_R, n_S, n_R):
    folder_path = 'outbox'
    i = 1
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        fileBinary = FileToBinary(file_path)
        print('m: ',ByteToBinary(fileBinary)[:100],'...',sep='')
        sssk = GenerateSSSK(128)
        print('SSSK: ',ByteToBinary(sssk)[:100],'...',sep='')
        cipherText, nonce = EncryptAES(ByteToBinary(fileBinary), sssk)
        print('{m}ₛₛₛₖ:',ByteToBinary(cipherText)[:100],'...',sep='')
        print('N: ',ByteToBinary(nonce)[:100],'...',sep='')
        hashDigest = Hash(fileBinary)
        hashBinary = ByteToBinary(HashToByte(hashDigest))
        print('{hashₛₕₐ₋₁(m)}: ',hashBinary[:100],'...',sep='')
        print('PR_S: ',PR_S)  
        print('PU_R: ',PU_R)
        cipherHashBinary = RSA_Encrypt(hashBinary, PR_S, n_S)
        print('{hashₛₕₐ₋₁(m)}ₚᵣ_ₛ: ',cipherHashBinary[:100],'...',sep='')
        cipherSSSK = RSA_Encrypt(ByteToBinary(sssk), int(PU_R), int(n_R))
        print('{SSSK}ₚᵤ_ᵣ: ',cipherSSSK[:100],'...',sep='')
        cipherNonce = RSA_Encrypt(ByteToBinary(nonce), int(PU_R), int(n_R))
        print('{N}ₚᵤ_ᵣ: ',cipherNonce[:100],'...',sep='')
        fileName = StringToBinary(os.path.basename(file_path))
        print('name: ',fileName[:100],'...',sep='')
        cipherName = RSA_Encrypt(fileName, int(PU_R), int(n_R))
        print('{name}ₚᵤ_ᵣ: ',cipherNonce[:100],'...',sep='')
        PGP_message = str(ByteToBinary(cipherText))+'||'+str(cipherHashBinary)+'||'+str(cipherSSSK)+'||'+str(cipherNonce)+'||'+str(cipherName)
        timestamp = str(datetime.now().strftime('%S-%M-%H-%d-%m-%y'))
        StringToFile(PGP_message, f'../user{recipient}/inbox/{sender.capitalize()}_{i}_{timestamp}.txt')
        i += 1

def DecryptFile(recipient, PR_R, n_R, PU_S, n_S):
    folder_path = f'inbox'
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        PGP_message = FileToString(file_path).split('||')
        file_name = RSA_Decrypt(PGP_message[4], PR_R, n_R)
        print('name: ', file_name[:100],'...',sep='')
        nonce = RSA_Decrypt(PGP_message[3], PR_R, n_R)
        print('N: ', nonce[:100],'...',sep='')
        sssk = RSA_Decrypt(PGP_message[2], PR_R, n_R)
        print('SSSK: ', sssk[:100],'...',sep='')
        hash_binary = RSA_Decrypt(PGP_message[1], PU_S, n_S)
        print('{hashₛₕₐ₋₁(m)}: ',hash_binary[:100],'...',sep='')
        file_binary = DecryptAES(BinaryToByte(PGP_message[0]), BinaryToByte(sssk), BinaryToByte(nonce))
        print('m: ', file_binary[:100],'...',sep='')
        hashDigest = Hash(BinaryToByte(file_binary))
        hashM = ByteToBinary(HashToByte(hashDigest))
        if hashM == hash_binary:
            BinaryToFile(BinaryToByte(file_binary),f'files/{BinaryToString(file_name)}')
            os.remove(file_path)

def PublicKeyRequest(Sender, Password, Destination):
    print("Sending Request to AS please wait")
    with open('../serverAS/MfromClient.txt', 'w') as output_file:
        output_file.write(f"{Sender}||{Destination}")

    # --- Waitng for serverAS to respond
    input("Please press Enter to continue...")

    with open('../user'+Sender+'/MfromAS.txt', 'r') as input_file:
        content1 = input_file.read()
        
    Messages = content1.strip().split('||')
    Messages = [Message.strip() for Message in Messages]
    print(f"Messages = {Messages}\n")
    MessageA = BinaryToByte(Messages[0])
    NonceA = BinaryToByte(Messages[1])
    MessageB = BinaryToByte(Messages[2])
    NonceB = BinaryToByte(Messages[3])
    print(f"MessageA = {MessageA}\n")
    print(f"NonceA = {NonceA}\n")

    # --- Decrypt messageA
    Passwordhash = Hashbit(StringToBinary(Password).encode())
    print(f"KeyA = {Passwordhash.encode}\n")
    Kc_TGS = DecryptAES(MessageA, Passwordhash.encode(), NonceA)
    print(f"Kc_TGS = {Kc_TGS}")
    print(f"Kc_TGS = {BinaryToByte(Kc_TGS)}")
    Messaged = Sender + "||" + Destination
    MessageD, NonceD = EncryptAES(StringToBinary(Messaged), BinaryToByte(Kc_TGS))

    print(f"{MessageD}")
    print(f"{StringToBinary(Destination)}||{ByteToBinary(MessageB)}||{ByteToBinary(NonceB)}||{ByteToBinary(MessageD)}||{ByteToBinary(NonceD)}")
    print("Sending Request to TGS please wait")
    with open('../serverTGS/MfromClient.txt', 'w') as output_file:
        output_file.write(f"{StringToBinary(Destination)}||{ByteToBinary(MessageB)}||{ByteToBinary(NonceB)}||{ByteToBinary(MessageD)}||{ByteToBinary(NonceD)}")

    # --- Waitng for serverTGS to respond
    input("Please press Enter to continue...")

    with open('../user'+Sender+'/MfromTGS.txt', 'r') as input_file:
        content2 = input_file.read()
        
    if content2 == "Wrong Password":
        raise ValueError("Wrong Password")

    Messagetgss = content2.strip().split('||')
    Messagetgss = [Messagetgs.strip() for Messagetgs in Messagetgss]
    print(f"Messages = {Messagetgss}\n")
    MessageF = BinaryToByte(Messagetgss[0])
    NonceF = BinaryToByte(Messagetgss[1])
    print(f"MessageF = {MessageF}")
    print(f"NonceF = {NonceF}")

    # --- Decrypt MessageF
    ContentF = DecryptAES(MessageF, BinaryToByte(Kc_TGS), NonceF)
    print(f"{BinaryToString(ContentF)}")
    Public_Keys = BinaryToString(ContentF).strip().split('||')
    Public_Keys = [value.strip() for value in Public_Keys]
    Public_Key = int(Public_Keys[0])
    n = int(Public_Keys[1])

    print(f"Public key of {Destination} = {Public_Key}")
    print(f"n of {Destination} = {n}")

    return Public_Key, n