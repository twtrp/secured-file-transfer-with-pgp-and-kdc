def DecimalToBinary(Decimal):
    return "{0:b}".format(int(Decimal))

def Modulo(Num, Power, Mod):
    Binarybits = DecimalToBinary(Power)
    Digit = 1
    for Bit in Binarybits:
        Digit = (Digit*Digit)%Mod
        if Bit != "0":
            Digit = (Digit*Num)%Mod
    return Digit

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

print("Result: %d" % (Modulo(80, 707, 1909)))
print("Result: %d" % (InvModulo(3,11)))
