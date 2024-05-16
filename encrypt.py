import math

def Modulo(Num, Power, Mod):
    Binarybits = DecimalToBinary(Power)
    Digit = 1
    for Bit in Binarybits:
        Digit = (Digit*Digit)%Mod
        if Bit != "0":
            Digit = (Digit*Num)%Mod
    return Digit

def DecimalToBinary(Decimal):
    return "{0:b}".format(int(Decimal))

def DecimalToBinarySpecifyBit(Decimal, Bit):
    return "{0:0{1}b}".format(Decimal, Bit)

def BinaryToDecimal(Binary):
    return int(Binary, 2)

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

def Plain_Spliting_Decrypt(Binary, n):
    Block_Size = math.floor(math.log2(n))+1 # calculate block size of plaintext
    result = [Binary[i:i+Block_Size] for i in range(0, len(Binary), Block_Size)] # separate into each block
    return result, Block_Size

def RSA_Decrypt(Message, Key, n):
    Result, Block_Size = Plain_Spliting_Decrypt(Message, n)
    Encrpyted_Decimal_Block = [BinaryToDecimal(Binary) for Binary in Result]
    Decimal_Block = [Modulo(Decimal, Key, n) for Decimal in Encrpyted_Decimal_Block]
    Decrypt_Binary_Block = [DecimalToBinarySpecifyBit(Decimal, Block_Size-1) for Decimal in Decimal_Block]
    
    # for i in range(len(Decrypted_Binary_Block)):
    #     if Decrypted_Binary_Block[i][-1] == '1' and '0' not in Decrypted_Binary_Block[i][:-1]:
    #         Decrypted_Binary_Block[i] = Decrypted_Binary_Block[i][:-1]
    
    Binary_Sequence = ''.join(Decrypt_Binary_Block) #join all block

    Last_One_Index = Binary_Sequence.rfind("1")
    Message = Binary_Sequence[:Last_One_Index] #from 0 to (Last_One_Index-1)th bit ไม่นับตัวเอง

    return Message


# test
Encrypt_Key = 77
Decrypt_Key = 53
binary_string = "1011000110101011"
n = 143
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
