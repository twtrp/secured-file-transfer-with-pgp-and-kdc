import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp2 import *  # Import functions from clientApp2.py

# Function to decrypt and write message from file
def decrypt_and_write_message(sender, recipient):
    # Read encrypted message from file
    file_path = f'./file_transmission/{sender}_to_{recipient}.txt'
    with open(file_path, 'r') as file:
        lines = file.readlines()
        encrypted_message = lines[0].split(': ')[1].strip()
        nonce = lines[1].split(': ')[1].strip()
        encrypted_hash = lines[2].split(': ')[1].strip()
        encrypted_sssk = lines[3].split(': ')[1].strip()

    # Decrypt the SSSK using recipient's private key
    sssk = RSA_Decrypt(ByteToBinary(encrypted_sssk), recipient_private_key[0], recipient_private_key[1])

    # Decrypt the message using AES with the SSSK and nonce
    decrypted_message = DecryptAES(encrypted_message.encode(), sssk, nonce.encode())

    # Calculate hash of the decrypted message
    decrypted_hash = Hash(decrypted_message.encode())

    # Decrypt the hash using sender's public key
    decrypted_hash = RSA_Decrypt(ByteToBinary(decrypted_hash), sender_public_key[0], sender_public_key[1])

    # Verify the integrity of the message
    if decrypted_hash == Hash(decrypted_message.encode()):
        # Write decrypted message to file in ../user/inbox
        with open(f'../user{recipient}/inbox/{sender}_to_{recipient}.txt', 'w') as file:
            file.write(decrypted_message)
    else:
        print("Error: message integrity verification failed.")

# Main function
if __name__ == "__main__":
    sender = "A"  # Example sender
    recipient = "B"  # Example recipient

    # Check if sender's public key exists
    if not os.path.exists(f'../user{sender}/key/PU_{sender}.txt'):
        print(f"Error: Public key for user {sender} does not exist.")
        sys.exit()

    # Check if recipient's private key exists
    if not os.path.exists(f'../user{recipient}/key/PR_{recipient}.txt'):
        print(f"Error: Private key for user {recipient} does not exist.")
        sys.exit()

    # Load sender's public key
    with open(f'../user{sender}/key/PU_{sender}.txt', 'r') as file:
        sender_public_key
