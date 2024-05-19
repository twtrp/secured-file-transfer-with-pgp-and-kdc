import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp2 import *  # Import functions from clientApp2.py

# Function to encrypt and write message to file
def encrypt_and_write_message(sender, recipient, message):
    """
    load message from ../userA/source/image.png
    FileToBinary(file_path): (from root/clientApp2.py)
    ByteToBinary(binary_data): (from root/clientApp2.py)
    """

    """
    collect message from ../userA/source/image.png
    FileToBinary(file_path): (from root/clientApp2.py)
    Hash(binary): (from root/clientApp2.py)
    HashToByte(hash_digest): (from root/clientApp2.py)
    ByteToBinary(binary_data): (from root/clientApp2.py)
    """

    # Generate a session symmetric key (SSSK)
    sssk = GenerateSSSK(128)

    # Encrypt the message using AES with the SSSK
    encrypted_message, nonce = EncryptAES(ByteToBinary(message_binary), sssk)

    # Calculate hash of the message
    message_hash = Hash(message_binary)

    # Convert hash to binary and encrypt it with sender's private key
    encrypted_hash = RSA_Encrypt(ByteToBinary(HashToByte(message_hash)), sender_private_key[0], sender_private_key[1])

    # Encrypt the SSSK using recipient's public key
    encrypted_sssk = RSA_Encrypt(ByteToBinary(sssk), recipient_public_key[0], recipient_public_key[1])

    # Write encrypted message and other information to file in ./file_transmission
    with open(f'./file_transmission/{sender}_to_{recipient}.txt', 'w') as file:
        file.write(f'Encrypted message: {encrypted_message}\n')
        file.write(f'Nonce: {nonce}\n')
        file.write(f'Encrypted Hash: {encrypted_hash}\n')
        file.write(f'Encrypted SSSK: {encrypted_sssk}\n')

# Main function
if __name__ == "__main__":
    sender = "A"  # Example sender
    recipient = "B"  # Example recipient

    # Check if recipient's public key exists
    if not os.path.exists(f'../user{recipient}/key/PU_{recipient}.txt'):
        print(f"Error: Public key for user {recipient} does not exist.")
        sys.exit()

    # Check if sender's private key exists
    if not os.path.exists(f'../user{sender}/key/PR_{sender}.txt'):
        print(f"Error: Private key for user {sender} does not exist.")
        sys.exit()

    # Load sender's private key
    with open(f'../user{sender}/key/PR_{sender}.txt', 'r') as file:
        sender_private_key = eval(file.read())

    # Load recipient's public key
    with open(f'../user{recipient}/key/PU_{recipient}.txt', 'r') as file:
        recipient_public_key = eval(file.read())

    # # Example message
    # message = "Hello, world!"

    # Load message from file
    file_path = f'../user{sender}/source/image.png'
    message_binary = FileToBinary(file_path)

    # Encrypt and write the message to file
    encrypt_and_write_message(sender, recipient, message_binary)
