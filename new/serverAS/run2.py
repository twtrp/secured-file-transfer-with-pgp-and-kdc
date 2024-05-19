import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from functions import *
import sqlite3

Kas_tgs = b"\xf6\x83\x8a|L\x9e\xca\xc5\xbb'H;\x88+&\x87"

while True:
    print('----------ServerAS----------')
    print("Options: '1' = Respond to requests")
    print("         '0' = Exit")
    option = input("► Select: ")
    if option == '1':
        folder_path = 'requests'
        request_list = os.listdir(folder_path)
        print(len(request_list))
        if len(request_list) == 0:
            print('■ Request inbox is empty. Press Enter to continue...')
        else:
            for request in request_list:
                file_path = os.path.join(folder_path, request)
                content = FileToString(file_path)
                values = content.split('||')
                sender = values[0]
                recipient = values[1]
                Kc_tgs = GenerateKeySSSK(128)
                binary_Kc_tgs = ByteToBinary(Kc_tgs)
                db = sqlite3.connect("userPasswords.sqlite").cursor()
                db.execute(f"SELECT password FROM userPasswords")
                result = db.fetchone()
                print(sender, recipient)
                print(result)
    elif option == "0":
        print('----------------------------')
        break
    else:
        input('■ Invalid option! Press Enter to continue...')