import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from functions import *

Kas_tgs = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

content1 = FileToString('Userpassword.txt')

passwords = content1.strip().split('||')
passwords = [password.strip() for password in passwords]

pass_A = Hashbit(StringToBinary(passwords[0]).encode())
pass_B = Hashbit(StringToBinary(passwords[1]).encode())
pass_C = Hashbit(StringToBinary(passwords[2]).encode())

# print(f"{pass_A.encode()}\n")
# print(f"{pass_B.encode()}\n")
# print(f"{pass_C.encode()}\n")

# load message from Client
with open('MfromClient.txt', 'r') as input_file:
    content2 = input_file.read()

Values = content2.strip().split('||')
Values = [Value.strip() for Value in Values]

Client = Values[0]
DesClient = Values[1]

# print(f"A: {Client}")
# print(f"B: {DesClient}")

# generate session key in unicode form, and change it to binarystring
Kc_tgs = GenerateKeySSSK(128)
# print(f"{Kc_tgs}")
binary_Kc_tgs = ByteToBinary(Kc_tgs)
# print(f"{binary_Kc_tgs}")

# example test
# Client = "B"

# encryptAES w/ key unicode

# message A & B and Nonce A & B return as unicode b'#
if Client == "A":
    message_A, nonce_A = EncryptAES(binary_Kc_tgs, pass_A.encode())
    # print(f"Key = {pass_A.encode()}")
elif Client == "B":
    message_A, nonce_A = EncryptAES(binary_Kc_tgs, pass_B.encode())
elif Client == "C":
    message_A, nonce_A = EncryptAES(binary_Kc_tgs, pass_C.encode())
    
messageb =  StringToBinary(Kc_tgs.hex()) + StringToBinary("||")+ StringToBinary(Client)
message_B, nonce_B = EncryptAES(messageb, Kas_tgs)

# print(f"{messageb}")
# print(f"{Kc_tgs.hex()}")
# print(f"{bytes.fromhex(Kc_tgs.hex())}")
# print(f"{BinaryToString(messageb)}")
# print(f"{ByteToBinary(message_A)}||{ByteToBinary(nonce_A)}||{ByteToBinary(message_B)}||{ByteToBinary(nonce_B)}")
with open('../user'+Client+'/MfromAS.txt', 'w') as output_file:
    output_file.write(f"{ByteToBinary(message_A)}||{ByteToBinary(nonce_A)}||{ByteToBinary(message_B)}||{ByteToBinary(nonce_B)}")