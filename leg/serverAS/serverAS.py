import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

Kas_tgs = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

# read password and hash each in specific length as Kc
with open('UserPassword.txt', 'r') as input_file:
    content1 = input_file.read()

Passwords = content1.strip().split('||')
Passwords = [Password.strip() for Password in Passwords]

PassA = Hashbit(StringToBinary(Passwords[0]).encode())
PassB = Hashbit(StringToBinary(Passwords[1]).encode())
PassC = Hashbit(StringToBinary(Passwords[2]).encode())

print(f"{PassA.encode()}\n")
print(f"{PassB.encode()}\n")
print(f"{PassC.encode()}\n")

# load message from Client
with open('MfromClient.txt', 'r') as input_file:
    content2 = input_file.read()

Values = content2.strip().split('||')
Values = [Value.strip() for Value in Values]

Client = Values[0]
DesClient = Values[1]

print(f"A: {Client}")
print(f"B: {DesClient}")

# generate session key in unicode form, and change it to binarystring
Kc_TGS = GenerateSSSK(128)
print(f"{Kc_TGS}")
BinaryKc_TGS = ByteToBinary(Kc_TGS)
print(f"{BinaryKc_TGS}")

# encryptAES w/ key unicode

# message A & B and Nonce A & B return as unicode b'#
if Client == "A":
    messageA, NonceA = EncryptAES(BinaryKc_TGS, PassA.encode())
    print(f"Key = {PassA.encode()}")
elif Client == "B":
    messageA, NonceA = EncryptAES(BinaryKc_TGS, PassB.encode())
elif Client == "C":
    messageA, NonceA = EncryptAES(BinaryKc_TGS, PassC.encode())
    
messageb =  StringToBinary(Kc_TGS.hex()) + StringToBinary("||")+ StringToBinary(Client)
messageB, NonceB = EncryptAES(messageb, Kas_tgs)

print(f"{messageb}")
print(f"{Kc_TGS.hex()}")
print(f"{bytes.fromhex(Kc_TGS.hex())}")
print(f"{BinaryToString(messageb)}")
print(f"{ByteToBinary(messageA)}||{ByteToBinary(NonceA)}||{ByteToBinary(messageB)}||{ByteToBinary(NonceB)}")
with open('../user'+Client+'/MfromAS.txt', 'w') as output_file:
    output_file.write(f"{ByteToBinary(messageA)}||{ByteToBinary(NonceA)}||{ByteToBinary(messageB)}||{ByteToBinary(NonceB)}")