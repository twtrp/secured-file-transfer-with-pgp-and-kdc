import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

KAS_TGS = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

# Access to everyone's password
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
# PU_A (Public Key for User A): 10918241545458707164346272246022548841
# n_A (Parameter for User A): 228228880681173030506413887301289747929
# PU_B (Public Key for User B): 66564982146357233858268702965596204459
# n_B (Parameter for User B): 172802230835666172654130396562467429321
# PU_C (Public Key for User C): 66564982146357233858268702965596204459
# n_C (Parameter for User C): 172802230835666172654130396562467429321

# Load message from Client
with open('MfromClient.txt', 'r') as input_file:
    content2 = input_file.read().strip()
# Message C:
# Destination: 01000010 (Binary representation of 'B')
# Message B: 001101110001010011011010000000010000000010011100110011111111110001011010111010011001000011110011111110010101101000110010100110001011101101010101
# Nonce B: 10010011110101100101001000111001110101100011000101100000101111011001010111011000001111110001111011101000111011000111110011011010
# Message D:
# Encrypted Message: 110001011001011011000001
# Nonce D: 01101001000010101111011111110001010010111000101101001110111100101110100111000110110000010011011001111000010010100110000001101010

# Splitting MessageC and MessageD
Messages = content2.strip().split('||')
if len(Messages) < 5:
    raise ValueError("MfromClient.txt must contain two messages separated by a comma.")

Destination = BinaryToString(Messages[0].strip())
MessageB = BinaryToByte(Messages[1].strip())
NonceB = BinaryToByte(Messages[2].strip())
MessageD = BinaryToByte(Messages[3].strip())
NonceD = BinaryToByte(Messages[4].strip())

# print(Destination)
# print(MessageB)
# print(NonceB)
# print(MessageD)
# print(NonceD)
# B
# b'7\x14\xda\x01\x00\x9c\xcf\xfcZ\xe9\x90\xf3\xf9Z2\x98\xbbU'
# b'\x93\xd6R9\xd61`\xbd\x95\xd8?\x1e\xe8\xec|\xda'
# b'\xc5\x96\xc1'
# b'i\n\xf7\xf1K\x8bN\xf2\xe9\xc6\xc16xJ`j'

# Decrypt MessageB and handle it correctly as bytes.
print(f"Nonce = {NonceB}")
print(f"MessageB = {MessageB}")
ContentB = DecryptAES(MessageB, KAS_TGS, NonceB)
print(f"ContentB = {ContentB}")
ByteContentB = BinaryToByte(ContentB)
print(f"ฺByteContentB = {ByteContentB}")
# Print ByteContentB as a hex string for analysis
print(f"ByteContentB (hex): {ByteContentB.hex()}")

# Decode bytes to a string to parse the actual contents.
# The issue lies in trying to decode binary data as UTF-8, which isn't always possible. 
"""
try:
    MessageB_parts = ByteContentB.decode('utf-8').strip().split(',')
    print(f"MessageB_parts = {MessageB_parts}")
except UnicodeDecodeError as e:
    print(f"Decoding Error: {e}")
    raise ValueError("Failed to decode ContentB as UTF-8. The data might be corrupted.")
"""
# Instead of decoding, let's handle the raw byte content
# Split ByteContentB based on known structure of the message (assuming it follows a specific pattern)
# Example: If ByteContentB contains data like Kc_TGS and ClientSourceAS separated by a specific delimiter
try:
    # Assuming the delimiter is a comma, split the byte content
    parts = ByteContentB.split(b',')
    print(f"Parts after split: {parts}")
    # Parts after split: [b';', b'\x1b>AK6\n\xb2\xeeca\xd5\xbd\xbc9', b'A']
    # there is 3 instead of expected 2
    # Messageb is composed of Kc_TGS, a comma, and the Client identifier.
    # This means ByteContentB would have the format Kc_TGS,Client, split by commas.

    # Ensure we have the expected number of parts
    if len(parts) != 3:
        raise ValueError("Unexpected number of parts after splitting ByteContentB.")
    
    AdditionalPart = parts[0].strip() # Handle the third part if needed
    Kc_TGS = parts[1].strip()
    ClientSourceAS = parts[2].strip()  
    print(f"AdditionalPart: {AdditionalPart}")
    print(f"Kc_TGS: {Kc_TGS}")
    print(f"ClientSourceAS: {ClientSourceAS}")
    # AdditionalPart: b';'
    # Kc_TGS: b'\x1b>AK6\n\xb2\xeeca\xd5\xbd\xbc9'
    # ClientSourceAS: b'A'
  
    AdditionalPart_str = AdditionalPart.decode('utf-8')
    print(f"AdditionalPart (decoded): {AdditionalPart_str}")
    Kc_TGS_str = Kc_TGS.decode('utf-8', errors='ignore')
    print(f"Kc_TGS (decoded): {Kc_TGS_str}")
    ClientSourceAS_str = ClientSourceAS.decode('utf-8')
    print(f"ClientSourceAS (decoded): {ClientSourceAS_str}")
    # AdditionalPart (decoded): ;
    # Kc_TGS (decoded): AK6
    # caս9
    # ClientSourceAS (decoded): A
except ValueError as e:
    print(f"Error splitting ByteContentB: {e}")
    raise ValueError("Failed to process ContentB. The data structure might be corrupted or incorrect.")

# Decrypt and handle MessageD
"""
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

"""

# Extra Message: Sending PU_A to Destination Client
# - encrypted w/ new SSSK as Kd_TGS (d=Destinnation)
Kd_TGS = GenerateSSSK(128)
print(f"{Kd_TGS}")
MessageExtra = PU_A + "||" + n_A
MessageExtraEncrypted, NonceExtra = EncryptAES(StringToBinary(MessageExtra), Kd_TGS)

# Write the extra message to a file for the destination client
extra_output_file_path = f'../user{Destination}/MessageExtra.txt'
with open(extra_output_file_path, 'w') as output_file:
    output_file.write(f"{ByteToBinary(MessageExtraEncrypted)}||{ByteToBinary(NonceExtra)}")

print(f"Extra message written to {extra_output_file_path}")