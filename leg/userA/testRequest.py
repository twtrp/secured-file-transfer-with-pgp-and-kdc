import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

def PublicKeyRequest(Sender, Password, Destination):
    print("Sending Request to AS please wait")
    with open('../serverAS/MfromClient.txt', 'w') as output_file:
        output_file.write(f"{Sender}||{Destination}")

    # --- Waitng for serverAS to respond
    input("Please press Enter to continue...")

    with open('MfromAS.txt', 'r') as input_file:
        content1 = input_file.read()
        
    messages = content1.strip().split('||')
    messages = [message.strip() for message in messages]
    print(f"messages = {messages}\n")
    messageA = BinaryToByte(messages[0])
    NonceA = BinaryToByte(messages[1])
    messageB = BinaryToByte(messages[2])
    NonceB = BinaryToByte(messages[3])
    print(f"messageA = {messageA}\n")
    print(f"NonceA = {NonceA}\n")

    # --- Decrypt messageA
    Passwordhash = Hashbit(StringToBinary(Password).encode())
    print(f"KeyA = {Passwordhash.encode}\n")
    Kc_TGS = DecryptAES(messageA, Passwordhash.encode(), NonceA)
    print(f"Kc_TGS = {Kc_TGS}")
    print(f"Kc_TGS = {BinaryToByte(Kc_TGS)}")
    messaged = Sender + "||" + Destination
    messageD, NonceD = EncryptAES(StringToBinary(messaged), BinaryToByte(Kc_TGS))

    print(f"{messageD}")
    print(f"{StringToBinary(Destination)}||{ByteToBinary(messageB)}||{ByteToBinary(NonceB)}||{ByteToBinary(messageD)}||{ByteToBinary(NonceD)}")
    print("Sending Request to TGS please wait")
    with open('../serverTGS/MfromClient.txt', 'w') as output_file:
        output_file.write(f"{StringToBinary(Destination)}||{ByteToBinary(messageB)}||{ByteToBinary(NonceB)}||{ByteToBinary(messageD)}||{ByteToBinary(NonceD)}")

    # --- Waitng for serverTGS to respond
    input("Please press Enter to continue...")

    with open('MfromTGS.txt', 'r') as input_file:
        content2 = input_file.read()
        
    if content2 == "Wrong Password":
        raise ValueError("Wrong Password")

    messagetgss = content2.strip().split('||')
    messagetgss = [messagetgs.strip() for messagetgs in messagetgss]
    print(f"messages = {messagetgss}\n")
    messageF = BinaryToByte(messagetgss[0])
    NonceF = BinaryToByte(messagetgss[1])
    print(f"messageF = {messageF}")
    print(f"NonceF = {NonceF}")

    # --- Decrypt messageF
    ContentF = DecryptAES(messageF, BinaryToByte(Kc_TGS), NonceF)
    print(f"{BinaryToString(ContentF)}")
    Public_Keys = BinaryToString(ContentF).strip().split('||')
    Public_Keys = [value.strip() for value in Public_Keys]
    Public_Key = int(Public_Keys[0])
    n = int(Public_Keys[1])

    print(f"Public key of {Destination} = {Public_Key}")
    print(f"n of {Destination} = {n}")

    return Public_Key, n

# --- Test
Password = input("Please enter password: ")
Destination = input("Which user do you want to send file to: ")
PublicKeyRequest("A", Password, Destination)