import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

Password = input("Please enter password: ")
Destination = input("Which user do you want to send file to: ")

print("Sending Request to AS please wait")
with open('../serverAS/MfromClient.txt', 'w') as output_file:
    output_file.write(f"A,{Destination}")

# --- Waitng for serverAS to respond
input("Please press Enter to continue...")

with open('MfromAS.txt', 'r', encoding=None) as input_file:
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
Messaged = "A," + Destination
MessageD, NonceD = EncryptAES(StringToBinary(Messaged), BinaryToByte(Kc_TGS))

print(f"{StringToBinary(Destination)}||{ByteToBinary(MessageB)}||{ByteToBinary(NonceB)}||{ByteToBinary(MessageD)}||{ByteToBinary(NonceD)}")
print("Sending Request to TGS please wait")
with open('../serverTGS/MfromClient.txt', 'w') as output_file:
    output_file.write(f"{StringToBinary(Destination)}||{ByteToBinary(MessageB)}||{ByteToBinary(NonceB)}||{ByteToBinary(MessageD)}||{ByteToBinary(NonceD)}")

# --- Waitng for serverTGS to respond
input("Please press Enter to continue...")
