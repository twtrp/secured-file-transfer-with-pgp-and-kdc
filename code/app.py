import sys
import libnum # for generate prime
import random # for general random

# --- Generate Prime Number
def generatePrime(bitsize):
    if (len(sys.argv)>1):
      bitsize=int(sys.argv[1])
    prime1=libnum.generate_prime(bitsize//2)
    prime2=libnum.generate_prime(bitsize - bitsize//2)
    n=prime1*prime2
    phi=(prime1-1)*(prime2-1)
    print ("\nPrime (p): %d. Length: %d bits, Digits: %d" % (prime1,libnum.len_in_bits(prime1), len(str(prime1))))  
    print ("\nPrime (q): %d. Length: %d bits, Digits: %d" % (prime2,libnum.len_in_bits(prime2), len(str(prime2))))
    print ("\nPrime (N): %d. Length: %d bits, Digits: %d" % (n,libnum.len_in_bits(n), len(str(n))))
    print ("\nPrime (phi): %d. Length: %d bits, Digits: %d" % (phi,libnum.len_in_bits(phi), len(str(phi))))  
    return n, prime1, prime2, phi # need to return p,q to cal phi n

# --- Decimal to Binary
def DecimalToBinary(Decimal):
    return "{0:b}".format(int(Decimal))

# --- Calculate Modulo
def Modulo(Num, Power, Mod):
    Binarybits = DecimalToBinary(Power)
    Digit = 1
    for Bit in Binarybits:
        Digit = (Digit*Digit)%Mod
        if Bit != "0":
            Digit = (Digit*Num)%Mod
    return Digit

# --- Calculate Inverse Modulo
def ExtEuclid(a, b):
    if b == 0:
        return (a, 1, 0)
    
    c1, x1, y1 = ExtEuclid(b, a % b)
    c = c1
    x = y1
    y = x1 - (a // b) * y1
    return (c, x, y)

def InvModulo(Num, Mod):
    gcd, x, y = ExtEuclid(Num, Mod)
    if gcd != 1:
        raise ValueError(f"No modular inverse exists for {Num} modulo {Mod}")
    else:
        return x % Mod

# --- Primitive root function here, return as array (all has same strength of n-1 order)
def gcd(a, b):
    a = int(a)
    b = int(b)
    while b != 0:
        a, b = b, a % b
    return a

# def is_primitive_root(g, n):
#     required_set = {num for num in range(1, n) if gcd(num, n) == 1}
#     actual_set = {pow(g, powers, n) for powers in range(1, n)}
#     return required_set == actual_set

# def find_primitive_root(n):
#     if n <= 1:
#         return []
#     if n == 2:
#         return [1]
    
#     phi = n - 1  # This is true for n being a prime number
#     factors = set()
#     x = phi
#     i = 2
#     while i * i <= x:
#         if x % i == 0:
#             factors.add(i)
#             while x % i == 0:
#                 x //= i
#         i += 1
#     if x > 1:
#         factors.add(x)
    
#     primitive_roots = []
#     for g in range(2, n):
#         if all(pow(g, phi // factor, n) != 1 for factor in factors):
#             primitive_roots.append(g)
#     return primitive_roots

# --- Generate key
def KeyGeneration(bitsize):
    n, p, q, phi = generatePrime(bitsize)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = InvModulo(e, phi)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

# Example usage:
# n = 17
bit = 16
primitive_root = find_primitive_root(n)
num, relatively_prime, randomnum = test(bit)
print(f"A primitive root modulo {n} is {primitive_root}")
print(f"A primitive root modulo {num} is {relatively_prime} random public key is {randomnum}")
