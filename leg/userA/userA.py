import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *
# from runCreateKey import *

# CreateKeyFile(A)

with open('key/PR_A.txt', 'r') as input_file:
    PR_key = input_file.read()
        
PR_keys = PR_key.strip().split(',')
PR_keys = [value.strip() for value in PR_keys]
PR_A = PR_keys[0]
n_A = PR_keys[1]

print(f"{PR_A}")

with open('key/PU_A.txt', 'r') as input_file:
    PU_key = input_file.read()

PU_keys = PU_key.strip().split(',')
PU_keys = [value.strip() for value in PU_keys]
PU_A = PU_keys[0]

work = True

while work:
    
    purpose = input("Do you want to \"send\" or \"read\" files (0 to exit): ")

    if purpose == "send":
        password = input("Please enter password: ")
        recipient = input("Which user do you want to send file to: ")
        PU_R, n_R = PublicKeyRequest("A", password, recipient)
        SendFile("A", recipient, int(PR_A), int(PU_R), int(n_A), int(n_R))

    elif purpose == "read":
        password = input("Please enter password: ")
        sender = input("Which user do you want to send file to: ")
        PU_S, n_S = PublicKeyRequest("A", password, sender)
        DecryptFile("A" , int(PR_A), int(n_A), int(PU_S), int(n_S))

    elif purpose == "0":
        work = False