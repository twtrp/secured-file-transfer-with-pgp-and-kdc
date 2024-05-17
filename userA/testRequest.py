from clientApp import *

Password = input("Please enter password: ")
Destination = input("Which user do you want to send file to: ")
print("Sending Request to AS please wait")

Request_Path = 'C:/Users/HP/Documents/GitHub/hungsecurity/serverAS/MfromClient.txt'
with open(Request_Path, 'w') as output_file:
    output_file.write(f"A,{Destination}")

# --- Waitng for serverAS to respond
input("Please press Enter to continue...")
print("Sending Request to TGS please wait")

with open('MfromAS.txt', 'r') as input_file:
    content1 = input_file.read()
    
Messages = content1.strip().split(',')
Messages = [Message.strip() for Message in Messages]

MessageA = Messages[0]
MessageB = Messages[1]
MessageC = "B," + MessageB

# --- Decrypt messageA
Kc_TGS = DecryptAES(MessageA, Hash(Password), nonce)
Messaged = "A," + nonce
MessageD = EncryptAES(Messaged, Kc_TGS)

RequestPU_Path = 'C:/Users/HP/Documents/GitHub/hungsecurity/serverTGS/MfromClient.txt'
with open(RequestPU_Path, 'w') as output_file:
    output_file.write(f"{MessageC},{MessageD}")

# --- Waitng for serverTGS to respond
input("Please press Enter to continue...")
