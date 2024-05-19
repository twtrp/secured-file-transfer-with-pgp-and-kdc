import hashlib
import random
import sys
import libnum
import math
import os
from Crypto.Cipher import DES3, AES
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
    e = random.randrange(2, phi)
    while GCD(e, phi) != 1:
        e = random.randrange(2, phi)
    d = InvModulo(e, phi)
    return e, d, n

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
    plain_text_byte = BinaryToByte(plain_text_bit)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text = cipher.encrypt(plain_text_byte)
    return cipher_text, nonce

def DecryptAES(cipher_text, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = ByteToBinary(cipher.decrypt(cipher_text))
    return plain_text

def SendFile(sender, recipient, PR_S, n_S, PU_R, n_R):
    folder_path = 'filesOut'
    i = 1
    file_list = os.listdir(folder_path)
    if len(file_list) == 0:
        input('■ You have no files to send in filesOut folder. Press Enter to continue...')
    else:
        for file_name in file_list:
            file_path = os.path.join(folder_path, file_name)
            file_binary = FileToBinary(file_path)
            sssk = GenerateKeySSSK(128)
            cipher_text, nonce = EncryptAES(ByteToBinary(file_binary), sssk)
            hash_digest = Hash(file_binary)
            hash_binary = ByteToBinary(HashToByte(hash_digest))
            cipher_hash_binary = EncryptRSA(hash_binary, PR_S, n_S)
            cipher_SSSK = EncryptRSA(ByteToBinary(sssk), PU_R, n_R)
            cipher_nonce = EncryptRSA(ByteToBinary(nonce), PU_R, n_R)
            cipherName = EncryptRSA(StringToBinary(file_name), PU_R, n_R)
            PGP_message = str(ByteToBinary(cipher_text))+'||'+str(cipher_hash_binary)+'||'+str(cipher_SSSK)+'||'+str(cipher_nonce)+'||'+str(cipherName)
            StringToFile(PGP_message, f'../transmissions/{sender.capitalize()}_{recipient.capitalize()}_{GetTimeStamp()}_{i}.txt')
            i += 1
            print(f'• Encrypted and sent {file_name}')
        input(f'■ Sending complete. Press Enter to continue...')

def DecryptFile(sender, recipient, PR_R, n_R, PU_S, n_S):
    folder_path = '../transmissions'
    count = 0
    for file_name in os.listdir(folder_path):
        if(file_name[0] == sender):
            if(file_name[2] == recipient):
                count += 1
                file_path = os.path.join(folder_path, file_name)
                PGP_message = FileToString(file_path).split('||')
                file_name = BinaryToString(DecryptRSA(PGP_message[4], PR_R, n_R))
                nonce = DecryptRSA(PGP_message[3], PR_R, n_R)
                sssk = DecryptRSA(PGP_message[2], PR_R, n_R)
                hash_binary = DecryptRSA(PGP_message[1], PU_S, n_S)
                file_binary = DecryptAES(BinaryToByte(PGP_message[0]), BinaryToByte(sssk), BinaryToByte(nonce))
                hashDigest = Hash(BinaryToByte(file_binary))
                hashM = ByteToBinary(HashToByte(hashDigest))
                if hashM == hash_binary:
                    BinaryToFile(BinaryToByte(file_binary),f'files/{file_name}')
                    print(f'• Successfully decrypted and stored {file_name}')
                else:
                    print(f'• Failed to verify integrity of {file_name}')
                os.remove(file_path)
    if count == 0:
        input('■ Your inbox is empty. Press Enter to continue...')
    else:
        input('■ All messages received. Press Enter to continue...')

def RequestPublicKey0(sender, password, destination):
    print("Sending Request to AS please wait")
    StringToFile(f"{sender}||{destination}", '../serverAS/MfromClient.txt')
    # --- Waitng for serverAS to respond
    input("Please press Enter to continue...")
    content1 = FileToString(f'../user{sender}/MfromAS.txt')
    messages = content1.strip().split('||')
    messages = [message.strip() for message in messages]
    # print(f"messages = {messages}\n")
    message_A = BinaryToByte(messages[0])
    nonce_A = BinaryToByte(messages[1])
    message_B = BinaryToByte(messages[2])
    nonce_B = BinaryToByte(messages[3])
    # print(f"messageA = {message_A}\n")
    # print(f"NonceA = {nonce_A}\n")
    # --- Decrypt messageA
    password_hash = Hashbit(StringToBinary(password).encode())
    # print(f"KeyA = {password_hash.encode}\n")
    Kc_tgs = DecryptAES(message_A, password_hash.encode(), nonce_A)
    # print(f"Kc_TGS = {Kc_tgs}")
    # print(f"Kc_TGS = {BinaryToByte(Kc_tgs)}")
    messaged = sender + "||" + destination
    message_D, NonceD = EncryptAES(StringToBinary(messaged), BinaryToByte(Kc_tgs))
    # print(f"{message_D}")
    # print(f"{StringToBinary(destination)}||{ByteToBinary(message_B)}||{ByteToBinary(nonce_B)}||{ByteToBinary(message_D)}||{ByteToBinary(NonceD)}")
    print("Sending Request to TGS please wait")
    StringToFile(f"{StringToBinary(destination)}||{ByteToBinary(message_B)}||{ByteToBinary(nonce_B)}||{ByteToBinary(message_D)}||{ByteToBinary(NonceD)}", '../serverTGS/MfromClient.txt')
    # --- Waitng for serverTGS to respond
    input("Please press Enter to continue...")
    content2 = FileToString(f'../user{sender}/MfromTGS.txt')
    if content2 == "Wrong password":
        raise ValueError("Wrong password")
    message_tgss = content2.strip().split('||')
    message_tgss = [message_tgs.strip() for message_tgs in message_tgss]
    # print(f"messages = {message_tgss}\n")
    messageF = BinaryToByte(message_tgss[0])
    nonce_F = BinaryToByte(message_tgss[1])
    # print(f"messageF = {messageF}")
    # print(f"NonceF = {nonce_F}")
    # --- Decrypt messageF
    content_F = DecryptAES(messageF, BinaryToByte(Kc_tgs), nonce_F)
    # print(f"{BinaryToString(content_F)}")
    public_keys = BinaryToString(content_F).strip().split('||')
    public_keys = [value.strip() for value in public_keys]
    public_key = int(public_keys[0])
    n = int(public_keys[1])
    # print(f"Public key of {destination} = {public_key}")
    # print(f"n of {destination} = {n}")
    return public_key, n

def RequestService(sender, password, mode, value):
    StringToFile(f'{sender}||{mode}||{value}', f'../transmissions/{sender}_AS_{GetTimeStamp()}.txt')
    print('• Sent request to AS')
    loop = True
    while loop:
        input('■ Press Enter after you receive response from AS...')
        folder_path = '../transmissions'
        for file_name in os.listdir(folder_path):
            if(file_name[0:2] == 'AS'):
                if(file_name[3] == sender):
                    file_path = os.path.join(folder_path, file_name)
                    content_AS = FileToString(file_path)
                    os.remove(file_path)
                    loop = False
                else:
                    print('• Response from AS is not received yet.')
            else:
                print('• Response from AS is not received yet.')
    segment_AS = content_AS.split('||')
    message_A = segment_AS[0]
    nonce_A = segment_AS[1]
    message_B = segment_AS[2]
    nonce_B = segment_AS[3]
    password_hash = Hashbit(StringToBinary(password).encode())
    Kc_tgs = DecryptAES(BinaryToByte(message_A), password_hash.encode(), BinaryToByte(nonce_A))
    message_C = StringToBinary(f'{mode}||{value}')
    message_D, nonce_D = EncryptAES(StringToBinary(sender), BinaryToByte(Kc_tgs))
    StringToFile(f'{message_C}||{message_B}||{nonce_B}||{ByteToBinary(message_D)}||{ByteToBinary(nonce_D)}', f'../transmissions/{sender}_TGS_{GetTimeStamp()}.txt')
    print('• Sent request to TGS')
    loop = True
    while loop:
        input('■ Press Enter after you receive response from TGS...')
        folder_path = '../transmissions'
        for file_name in os.listdir(folder_path):
            if(file_name[0:3] == 'TGS'):
                if(file_name[4] == sender):
                    file_path = os.path.join(folder_path, file_name)
                    content_TGS = FileToString(file_path)
                    os.remove(file_path)
                    loop = False
                else:
                    print('• Response from TGS is not received yet.')
            else:
                print('• Response from TGS is not received yet.')
    if content_TGS == 'Denied':
        return 0, 0
    else:
        if mode == '0':
            segment_TGS = content_TGS.split('||')

        elif mode == '1':
            if content_TGS == 'Updated':
                return 1
                input('■ Your public key has been updated. Press Enter to continue...')
            else:
                return 0
                input('■ Error. Your public key was not updated. Press Enter to continue...')