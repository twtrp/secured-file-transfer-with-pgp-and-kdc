import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from functions import *
import sqlite3

Kas_tgs = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

while True:
    print('----------ServerAS----------')
    print("Options: 'Enter' = Respond to auth requests")
    print("         '0' = Exit")
    option = input("► Select: ")
    if option == '':
        count = 0
        folder_path = '../transmissions'
        request_list = os.listdir(folder_path)
        for file_name in os.listdir(folder_path):
            if(file_name[2:4] == 'AS'):
                count += 1
                sender = file_name[0]
                file_path = os.path.join(folder_path, file_name)
                content = FileToString(file_path)
                os.remove(file_path)
                values = content.split('||')
                if values[0] != sender:
                    print('• Corrupt request message')
                else:
                    mode = values[1]
                    value = values[2]
                    Kc_tgs = GenerateKeySSSK(128)
                    binary_Kc_tgs = ByteToBinary(Kc_tgs)
                    db = sqlite3.connect("userPasswords.sqlite").cursor()
                    db.execute(f"SELECT password FROM userPasswords WHERE user == '{sender}'")
                    Pc = db.fetchone()[0]
                    Kc = Hashbit(StringToBinary(Pc).encode())
                    message_A, nonce_A = EncryptAES(binary_Kc_tgs, Kc.encode())
                    plain_B = StringToBinary(f'{Kc_tgs.hex()}||{sender}||{mode}||{value}')
                    message_B, nonce_B = EncryptAES(plain_B, Kas_tgs)
                    StringToFile(f'{ByteToBinary(message_A)}||{ByteToBinary(nonce_A)}||{ByteToBinary(message_B)}||{ByteToBinary(nonce_B)}', f'../transmissions/AS_{sender}_{GetTimeStamp()}.txt')
                    if mode == '0':
                        print(f'• Responded to {sender}\'s request for {value}\'s PU')
                    elif mode == '1':
                        print(f'• Responded to {sender}\'s request for changing their PU')
        if count == 0:
            print('• There are no requests.')
        else:
            print('• Requests cleared.')
    elif option == "0":
        print('----------------------------')
        break
    else:
        print('• Invalid option!')