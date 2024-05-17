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
MessageA = Messages[0][2:-1]
NonceA = Messages[1][2:-1]
MessageB = Messages[2][2:-1]
NonceB = Messages[3][2:-1]
MessageC = "B," + MessageB
print(f"MessageC = {MessageC}\n")
print(f"MessageA = {MessageA}\n")
print(f"MessageA = {NonceA.encode()}\n")

# --- Decrypt messageA
Passwordhash = Hashbit(StringToBinary(Password).encode())
print(f"MessageA = {Passwordhash.encode()}\n")
Kc_TGS = DecryptAES(MessageA.encode(), Passwordhash.encode(), NonceA.encode())
print(f"Kc_TGS = {Kc_TGS}")
print(f"Kc_TGS = {BinaryToByte(Kc_TGS)}")
Messaged = "A," + Destination
MessageD, NonceD = EncryptAES(StringToBinary(Messaged), BinaryToByte(Kc_TGS))

print("Sending Request to TGS please wait")
with open('../serverTGS/MfromClient.txt', 'w') as output_file:
    output_file.write(f"{MessageC},{NonceB},{MessageD},{NonceD}")

# --- Waitng for serverTGS to respond
input("Please press Enter to continue...")
