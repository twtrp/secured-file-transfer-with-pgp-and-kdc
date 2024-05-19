import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from functions import *

PR_key = FileToString('keys/PR_B.txt')
        
PR_keys = PR_key.strip().split(',')
PR_keys = [value.strip() for value in PR_keys]
PR_B = PR_keys[0]
n_B = PR_keys[1]

PU_key = FileToString('keys/PU_B.txt')

PU_keys = PU_key.strip().split(',')
PU_keys = [value.strip() for value in PU_keys]
PU_B = PU_keys[0]

work = True

while work:
    
    purpose = input("Do you want to \"send\" or \"read\" files (0 to exit): ")

    if purpose == "send":
        password = input("Please enter password: ")
        recipient = input("Which user do you want to send file to: ")
        PU_R, n_R = PublicKeyRequest("B", password, recipient)
        SendFile("B", recipient, int(PR_B), int(PU_R), int(n_B), int(n_R))

    elif purpose == "read":
        password = input("Please enter password: ")
        sender = input("Which user sent file to you: ")
        PU_S, n_S = PublicKeyRequest("B", password, sender)
        DecryptFile("B" , int(PR_B), int(n_B), int(PU_S), int(n_S))

    elif purpose == "0":
        work = False