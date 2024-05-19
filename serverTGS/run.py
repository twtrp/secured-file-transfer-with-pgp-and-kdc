import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from functions import *
import sqlite3

Kas_tgs = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

while True:
    print('----------ServerTGS----------')
    print("Options: 'Enter' = Respond to service requests")
    print("         '0' = Exit")
    option = input("► Select: ")
    if option == '':
        count = 0
        folder_path = '../transmissions'
        request_list = os.listdir(folder_path)
        for file_name in os.listdir(folder_path):
            if(file_name[2:5] == 'TGS'):
                count += 1
                sender = file_name[0]
                file_path = os.path.join(folder_path, file_name)
                content = FileToString(file_path)
                os.remove(file_path)
                segment = content.split('||')
                service = segment[0]
                message_B = segment[1]
                nonce_B = segment[2]
                message_D = segment[3]
                nonce_D = segment[4]
                service = BinaryToString(service).split('||')
                mode_C = service[0]
                value_C = service[1]
                plain_B = BinaryToString(DecryptAES(BinaryToByte(message_B), Kas_tgs, BinaryToByte(nonce_B))).split('||')
                Kc_tgs = bytes.fromhex(plain_B[0])
                sender_B = plain_B[1]
                mode_B = plain_B[2]
                value_B = plain_B[3]
                plain_D = DecryptAES(BinaryToByte(message_D), Kc_tgs, BinaryToByte(nonce_D))
                sender_D = BinaryToString(plain_D)
                if (sender_B == sender_D) & (mode_B == mode_C) & (value_B == value_C):
                    sender = sender_B
                    mode = mode_B
                    value = value_B
                    if mode == '0':
                        conn = sqlite3.connect("userPublicKeys.sqlite")
                        db = conn.cursor()
                        db.execute(f'SELECT `publicKey` FROM `userPublicKeys` WHERE `user` == "{value}"')
                        PU = db.fetchone()[0]
                        db.execute(f'SELECT `n` FROM `userPublicKeys` WHERE `user` == "{value}"')
                        n = db.fetchone()[0]
                        conn.close()
                        plain_E = f'{PU},{n}'
                        message_E, nonce_E = EncryptAES(StringToBinary(plain_E), Kc_tgs)
                        StringToFile(f'{ByteToBinary(message_E)}||{ByteToBinary(nonce_E)}', f'../transmissions/TGS_{sender}_{GetTimeStamp()}.txt')
                        print(f'• Responded to {sender}\'s request and sent {value}\'s PU')
                    elif mode == '1':
                        full_PU = value.split(',')
                        PU = full_PU[0]
                        n = full_PU[1]
                        conn = sqlite3.connect("userPublicKeys.sqlite")
                        db = conn.cursor()
                        db.execute(f'UPDATE `userPublicKeys` SET `publicKey` = "{PU}", `n` = "{n}" WHERE `user` == "{sender}"')
                        conn.commit()
                        conn.close()
                        StringToFile('Updated', f'../transmissions/TGS_{sender}_{GetTimeStamp()}.txt')
                        print(f'• Responded to {sender}\'s request and changed their PU')
                else:
                    StringToFile('Denied', f'../transmissions/TGS_{sender}_{GetTimeStamp()}.txt')
                    print(f'• Denied {sender}\'s request due to incorrect password.')
        if count == 0:
            input('■ There are no requests. Press Enter to continue...')
        else:
            input('■ Requests cleared. Press Enter to continue...')
    elif option == "0":
        print('----------------------------')
        break
    else:
        print('• Invalid option!')