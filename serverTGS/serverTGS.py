import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

KAS_TGS = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

# access to everyone's password
with open('UserPassword.txt', 'r') as input_file:
    content1 = input_file.read()

Keys = content1.strip().split(',')
Keys = [Key.strip() for Key in Keys]

PU_A = Keys[0]
PU_B = Keys[1]
PU_C = Keys[2]

# load message from Client
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
NonceB = MessageCs[2]

# --- Decrypt and Split MessageB
ContentB = DecryptAES(MessageB, KAS_TGS, NonceB)
MessageBs = ContentB.strip().split(',')
MessageBs = [Message.strip() for Message in MessageBs]

Kc_TGS = MessageBs[0]
ClientinB = MessageBs[1]

# --- Split MessageD
MessageDs = MessageD.strip().split(',')
MessageDs = [Message.strip() for Message in MessageDs]

ClientinD = MessageDs[0]
nonceD = MessageDs[1]

# --- Sending Key
if DesClient == "A":
    ResMessage = EncryptAES(PU_A, Kc_TGS)
elif DesClient == "B":
    ResMessage = EncryptAES(PU_B, Kc_TGS)
elif DesClient == "C":
    ResMessage = EncryptAES(PU_C, Kc_TGS)

with open('output_file.txt', 'w') as output_file:
    output_file.write(f"{ResMessage}")