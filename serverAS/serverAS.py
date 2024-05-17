from clientApp import *

KAS_TGS = ""

with open('UserPassword.txt', 'r') as input_file:
    content1 = input_file.read()

Passwords = content1.strip().split(',')
Passwords = [Password.strip() for Password in Passwords]

PassA = Hash(Passwords[0])
PassB = Hash(Passwords[1])
PassC = Hash(Passwords[2])

with open('MfromClient.txt', 'r') as input_file:
    content2 = input_file.read()

Values = content2.strip().split(',')
Values = [Value.strip() for Value in Values]

Client = Values[0]
DesClient = Values[1]

print(f"A: {Client}")
print(f"B: {DesClient}")

Kc_TGS = GenerateSSSK(128)
if Client == "A":
    MessageA, nonce1 = EncryptAES(Kc_TGS, PassA)
elif Client == "B":
    MessageA, nonce1 = EncryptAES(Kc_TGS, PassB)
elif Client == "C":
    MessageA, nonce1 = EncryptAES(Kc_TGS, PassC)
    
Messageb = Kc_TGS + "," + Client
MessageB, nonce2 = EncryptAES(Messageb, KAS_TGS)

Respond_Path = 'C:/Users/HP/Documents/GitHub/hungsecurity/userA/MfromAS.txt'
with open(Respond_Path, 'w') as output_file:
    output_file.write(f"{MessageA},{MessageB}")