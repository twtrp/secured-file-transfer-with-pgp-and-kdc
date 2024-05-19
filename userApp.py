import sys
import os
from functions import *

def userApp(user):

    try:
        PR_user = FileToString(f'keys/PR_{user}.txt')
        n_user = FileToString(f'keys/n_{user}.txt')
    except FileNotFoundError:
        password = input('► Enter password: ')
        bitsize = 1024
        PU, PR, n = GenerateKeyRSA(bitsize)
        status = RequestService(user, password, '1', f'{PU},{n}')
        if status == 1:
            StringToFile(str(PU), f'keys/PU_{user}.txt')
            StringToFile(str(PR), f'keys/PR_{user}.txt')
            StringToFile(str(n), f'keys/n_{user}.txt')
            input('■ Your public key has been updated. Press Enter to continue...')
        else: 
            input('■ Error. Your public key was not updated. Press Enter to continue...')

    while True:
        print(f'----------User{user}----------')
        print("Options: 's' = Send files")
        print("         'r' = Receive files")
        print("         'k' = Generate new key pair")
        print("         '0' = Exit")
        option = input('► Select: ').lower()
        if option == 's':
            password = input('► Enter password: ')
            while True:
                recipient = input('► Which user to send file to: ').capitalize()
                if recipient == user:
                    print('• You can\'t send to yourself.')
                else:
                    PU_R, n_R = RequestService(user, password, '0', recipient)
                    if PU_R == 0:
                        input('■ Password was incorrect. Press Enter to continue...')
                        break
                    else:
                        SendFile(user, recipient, int(PR_user), int(n_user), int(PU_R), int(n_R))
                        break
        elif option == 'r':
            password = input('► Enter password: ')
            sender = input('► Which user sent file to you: ').capitalize()
            PU_S, n_S = RequestService(user, password, '0', sender)   
            if PU_S == 0:
                input('■ Password was incorrect. Press Enter to continue...')
                break
            else:
                DecryptFile(sender, user, int(PR_user), int(n_user), int(PU_S), int(n_S))
        elif option == 'k':
            password = input('► Enter password: ')
            bitsize = 1042
            PU, PR, n = GenerateKeyRSA(bitsize)
            status = RequestService(user, password, '1', f'{PU},{n}')
            if status == 1:
                StringToFile(str(PU), f'keys/PU_{user}.txt')
                StringToFile(str(PR), f'keys/PR_{user}.txt')
                StringToFile(str(n), f'keys/n_{user}.txt')
                input('■ Your public key has been updated. Press Enter to continue...')
            else: 
                input('■ Error. Your public key was not updated. Press Enter to continue...')
        elif option == '0':
            print('-------------------------')
            break
        else:
            input('■ Invalid option! Press Enter to continue...')