import hashlib

def StringToTuple(string):
    return eval(string)

def FileToBinary(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()
    return binary_data

def BinaryToFile(binary_data, output_file_path):
    with open(output_file_path, 'wb') as file:
        file.write(binary_data)

def FileToString(file_path):
    with open(file_path, 'r') as file:
        string = file.read()
    return string
    
def StringToFile(string, output_file_path):
    with open(output_file_path, 'w') as file:
        file.write(string)
        
def Hash(binary):
    return hashlib.sha256(binary).hexdigest()

def Hashbit(binary):
    hash_value = hashlib.sha256(binary).hexdigest()
    byte_hash = hash_value[:32] 
    return byte_hash

def HashToByte(hash_digest):
    hash_bytes = bytes.fromhex(hash_digest)
    return hash_bytes

def ByteToBinary(binary_data):
    return ''.join(format(byte, '08b') for byte in binary_data)

def BinaryToByte(binary_string):
    byte_data = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    int_data = [int(byte, 2) for byte in byte_data]
    byte_string = bytes(int_data)
    return byte_string

def StringToBinary(string):
    return ''.join(format(ord(char), '08b') for char in string)

def BinaryToString(binary):
    if len(binary) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")
    if any(char not in '01' for char in binary):
        raise ValueError("Binary string must contain only '0' or '1'")
    bytes = [binary[i:i+8] for i in range(0, len(binary), 8)]
    text = "".join([chr(int(byte, 2)) for byte in bytes])
    return text

def DecimalToBinary(decimal):
    return "{0:b}".format(int(decimal))

def DecimalToBinarySpecifyBit(decimal, bit):
    return "{0:0{1}b}".format(decimal, bit)

def BinaryToDecimal(binary):
    return int(binary, 2)