import sys
import libnum # for generate prime
import random # for general random
import math
from PIL import Image
import io
import hashlib

# --- Generate Prime Number
def GeneratePrime(bitsize):
    if (len(sys.argv)>1):
      bitsize=int(sys.argv[1])
    prime1=libnum.generate_prime(bitsize//2)
    prime2=libnum.generate_prime(bitsize - bitsize//2)
    n=prime1*prime2
    phi=(prime1-1)*(prime2-1)
    # print ("\nPrime (p): %d. Length: %d bits, Digits: %d" % (prime1,libnum.len_in_bits(prime1), len(str(prime1))))  
    # print ("\nPrime (q): %d. Length: %d bits, Digits: %d" % (prime2,libnum.len_in_bits(prime2), len(str(prime2))))
    # print ("\nPrime (N): %d. Length: %d bits, Digits: %d" % (n,libnum.len_in_bits(n), len(str(n))))
    # print ("\nPrime (phi): %d. Length: %d bits, Digits: %d" % (phi,libnum.len_in_bits(phi), len(str(phi))))  
    return n, prime1, prime2, phi # need to return p,q to cal phi n

# --- Decimal to Binary
def DecimalToBinary(Decimal):
    return "{0:b}".format(int(Decimal))

def DecimalToBinarySpecifyBit(Decimal, Bit):
    return "{0:0{1}b}".format(Decimal, Bit)

# --- Binary to Decimal
def BinaryToDecimal(Binary):
    return int(Binary, 2)

# --- Calculate Modulo
def Modulo(Num, Power, Mod):
    Binarybits = DecimalToBinary(Power)
    Digit = 1
    for Bit in Binarybits:
        Digit = (Digit*Digit)%Mod
        if Bit != "0":
            Digit = (Digit*Num)%Mod
    return Digit

# --- Calculate Inverse Modulo
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

# --- gcd
def gcd(a, b):
    a = int(a)
    b = int(b)
    while b != 0:
        a, b = b, a % b
    return a

# --- Generate key
def GenerateKey(bitsize):
    n, p, q, phi = GeneratePrime(bitsize)
    e1 = random.randrange(2, phi)
    while gcd(e1, phi) != 1:
        e1 = random.randrange(2, phi)
    d1 = InvModulo(e1, phi)
    public_key_A = (e1, n)
    private_key_A = (d1, n)
    
    e2 = random.randrange(2, phi)
    while gcd(e2, phi) != 1:
        e2 = random.randrange(2, phi)
        if e2 == e1:
            e2 = random.randrange(2, phi)
    d2 = InvModulo(e2, phi)
    public_key_B = (e2, n)
    private_key_B = (d2, n)

    e3 = random.randrange(2, phi)
    while gcd(e3, phi) != 1:
        e3 = random.randrange(2, phi)
        if e3 == e2 | e3 == e1:
            e3 = random.randrange(2, phi)
    d3 = InvModulo(e3, phi)
    public_key_C = (e3, n)
    private_key_C = (d3, n)

    return public_key_A, private_key_A, public_key_B, private_key_B, public_key_C, private_key_C

# --- RSA Encryption
def Plain_Spliting_Encypt(Binary, n):
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
    Result, Block_Size = Plain_Spliting_Encypt(Message, n)
    Decimal_Block = [BinaryToDecimal(Binary) for Binary in Result]
    Encrpyt_Decimal_Block = [Modulo(Decimal, Key, n) for Decimal in Decimal_Block]
    # change into form of block_size + 1 bit
    Encrpyt_Binary_Block = [DecimalToBinarySpecifyBit(Decimal, Block_Size+1) for Decimal in Encrpyt_Decimal_Block]
    Cipher_Binary_Sequence = ''.join(Encrpyt_Binary_Block) #join all block
    return Cipher_Binary_Sequence

# --- RSA Decryption
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


# Example usage:
# primitive_root = find_primitive_root(n)
# num, relatively_prime, randomnum = test(bit)
# print(f"A primitive root modulo {n} is {primitive_root}")
# print(f"A primitive root modulo {num} is {relatively_prime} random public key is {randomnum}")

# key generate test
bit = 40
PU_A, PR_A, PU_B, PR_B, PU_C, PR_C = GenerateKey(bit)
print(f"public_key_A is {PU_A}, private_key_A is {PR_A}, public_key_B is {PU_B}, private_key_B is {PR_B}, public_key_C is {PU_C}, private_key_C is {PR_C}")  

Encrypt_Key = PU_A[0]
Decrypt_Key = PR_A[0]
binary_string = "1011000110101011"
n = PU_A[1]
# Plain_Spliting, Block_Size = Plain_Spliting_Encypt(binary_string, n)
# print(f"{Plain_Spliting}")
# Decimal_Block = [BinaryToDecimal(Binary) for Binary in Plain_Spliting]
# Encrpyt_Decimal_Block = [Modulo(Decimal, Key, n) for Decimal in Decimal_Block]
# Encrpyt_Binary_Block = [DecimalToBinarySpecifyBit(Decimal, Block_Size) for Decimal in Encrpyt_Decimal_Block]
# print(f"{Encrpyt_Binary_Block}")
RSA=RSA_Encrypt(binary_string, Encrypt_Key, n)
print(f"{RSA}")
Plaintext=RSA_Decrypt(RSA, Decrypt_Key, n)
print(f"{Plaintext}")
