import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

KAS_TGS = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

# access to everyone's password
with open('UserPublicKey.txt', 'r') as input_file:
    content1 = input_file.read()

Keys = content1.strip().split('||')
Keys = [Key.strip() for Key in Keys]

PU_A = Keys[0]
n_A = Keys[1]
PU_B = Keys[2]
n_B = Keys[3]
PU_C = Keys[4]
n_C = Keys[5]
# PU_C and n_C is copy of B right now

# load message from Client
with open('MfromClient.txt', 'r') as input_file:
    content2 = input_file.read().strip()

# Splitting MessageC and MessageD
Messages = content2.strip().split('||')
if len(Messages) < 2:
    raise ValueError("MfromClient.txt must contain two messages separated by a comma.")

Destination = BinaryToString(Messages[0].strip())
MessageB = BinaryToByte(Messages[1].strip())
NonceB = BinaryToByte(Messages[2].strip())
MessageD = BinaryToByte(Messages[3].strip())
NonceD = BinaryToByte(Messages[4].strip())

# Decrypt and Split MessageB
print(f"{NonceB}")
print(f"{MessageB}")
ContentB = DecryptAES(MessageB, KAS_TGS, NonceB)
ByteContentB = BinaryToByte(ContentB)
print(f"ContentB = {ByteContentB}")
MessageB_parts = ByteContentB.strip().split(',')

Kc_TGS = MessageB_parts[0].strip()
print(f"Kc = {BinaryToByte(StringToBinary(Kc_TGS))}")
ClientSourceAS = MessageB_parts[1].strip()
print(f"Client = {ClientSourceAS}\n")
# Decrypt and Split MessageD
ContentD = DecryptAES(MessageD , BinaryToByte(StringToBinary(Kc_TGS)), NonceD)
StringContentD = BinaryToString(ContentD)
print(f"StringD = {StringContentD}")
MessageD_parts = ContentD.strip().split(',')

print(f"{MessageD_parts}")
ClientSourceTGS = MessageD_parts[0].strip()
Destination = MessageD_parts[1].strip()

#Test Case
# ClientSourceAS = A
# Destination = B
if ClientSourceTGS != ClientSourceAS:
    raise ValueError("Wrong Password")

# Determine the public key to use for encryption based on DesClient
if Destination == "A":
    public_key = PU_A
    n = n_A
elif Destination == "B":
    public_key = PU_B
    n = n_B
elif Destination == "C":
    public_key = PU_C
    n = n_C
else:
    raise ValueError("Unknown destination client")

# Encrypt the session key with the appropriate public key
Messagef = public_key + "||" + n
MessageF = EncryptAES(StringToBinary(Messagef), Kc_TGS)

# Write the response to the output file for SrcClient
print(f"{ByteToBinary(MessageF)}")
output_file_path = f'../user{ClientSourceTGS}/MfromTGS.txt'
with open(output_file_path, 'w') as output_file:
    output_file.write(f"{ByteToBinary(MessageF)}")

print(f"Response written to {output_file_path}")
