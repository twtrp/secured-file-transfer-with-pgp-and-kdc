from clientApp import *

KAS_TGS = ""

with open('UserPassword.txt', 'r') as input_file:
    content1 = input_file.read()

Keys = content1.strip().split(',')
Keys = [Key.strip() for Key in Keys]

PU_A = Hash(Keys[0])
PU_B = Hash(Keys[1])
PU_C = Hash(Keys[2])

with open('MfromClient.txt', 'r') as input_file:
    content2 = input_file.read()
    
Messages = content2.strip().split(',')
Messages = [Message.strip() for Message in Messages]

MessageC = Messages[0]
MessageD = Messages[1]

# --- Split MessageC
MessageCs = MessageC.strip().split(',')
MessageCs = [Message.strip() for Message in MessageCs]

DesClient = MessageCs[0]
MessageB = MessageCs[1]

# --- Decrypt and Split MessageB
ContentB = DecryptAES(MessageB, KAS_TGS, nonce)
MessageBs = ContentB.strip().split(',')
MessageBs = [Message.strip() for Message in MessageBs]

Kc_TGS = MessageBs[0]
ClientinB = MessageBs[1]

# --- Split MessageD
MessageDs = MessageD.strip().split(',')
MessageDs = [Message.strip() for Message in MessageDs]

ClientinD = MessageDs[0]
nonce = MessageDs[1]

# --- Sending Key
if DesClient == "A":
    ResMessage = EncryptAES(PU_A, Kc_TGS)
elif DesClient == "B":
    ResMessage = EncryptAES(PU_B, Kc_TGS)
elif DesClient == "C":
    ResMessage = EncryptAES(PU_C, Kc_TGS)

with open('output_file.txt', 'w') as output_file:
    output_file.write(f"{ResMessage}")