import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from functions import *

PR_key = FileToString('keys/PR_A.txt')
PR_keys = PR_key.strip().split(',')
PR_keys = [value.strip() for value in PR_keys]
PR_A = PR_keys[0]
n_A = PR_keys[1]

PU_key = FileToString('keys/PU_A.txt')
PU_keys = PU_key.strip().split(',')
PU_keys = [value.strip() for value in PU_keys]
PU_A = PU_keys[0]

while True:
    print('----------UserA----------')
    print("Options: 's' = Send files")
    print("         'r' = Receive files")
    print("         'k' = Generate new key pair")
    print("         '0' = Exit")
    option = input("► Select: ")
    if option == "s":
        password = input("Please enter password: ")
        recipient = input("Which user do you want to send file to: ")
        PU_R, n_R = PublicKeyRequest("A", password, recipient)
        SendFile("A", recipient, int(PR_A), int(PU_R), int(n_A), int(n_R))
    elif option == "r":
        password = input("Please enter password: ")
        sender = input("Which user sent file to you: ")
        PU_S, n_S = PublicKeyRequest("A", password, sender)
        DecryptFile("A" , int(PR_A), int(n_A), int(PU_S), int(n_S))
    elif option == "0":
        print('-------------------------')
        break
    else:
        input('■ Invalid option! Press Enter to continue...')