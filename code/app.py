import sys
import libnum

def generatePrime(bitsize):
   if (len(sys.argv)>1):
      bitsize=int(sys.argv[1])
   r=libnum.randint_bits(bitsize)
   p=libnum.generate_prime(bitsize)
   q=libnum.generate_prime(bitsize)
   n=p*q
   print ("Random: %d Length: %d" % (r,libnum.len_in_bits(r)))
   print ("\nPrime (p): %d. Length: %d bits, Digits: %d" % (p,libnum.len_in_bits(p), len(str(p))))  
   print ("\nPrime (q): %d. Length: %d bits, Digits: %d" % (q,libnum.len_in_bits(q), len(str(q))))
   print ("\nPrime (N): %d. Length: %d bits, Digits: %d" % (n,libnum.len_in_bits(n), len(str(n)))) 
   return n # need to return p,q to cal phi n

# --- Primitive root function here, return as array (all has same strength of n-1 order)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_primitive_root(g, n):
    required_set = {num for num in range(1, n) if gcd(num, n) == 1}
    actual_set = {pow(g, powers, n) for powers in range(1, n)}
    return required_set == actual_set

def find_primitive_root(n):
    if n == 1:
        return None
    if n == 2:
        return 1
    
    phi = n - 1  # This is true for n being a prime number
    factors = set()
    x = phi
    i = 2
    while i * i <= x:
        if x % i == 0:
            factors.add(i)
            while x % i == 0:
                x //= i
        i += 1
    if x > 1:
        factors.add(x)
    
    for g in range(2, n):
        if all(pow(g, phi // factor, n) != 1 for factor in factors):
            return g
    return None

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

# Example usage:
n = 17
primitive_root = find_primitive_root(n)
print(f"A primitive root modulo {n} is {primitive_root}")





## rand.e that is primitive root of n