#Nathan Todd
#Program: modular_math
#Square-and-multiply modular exponentiation used for every Diffie-Hellman calculation.


#Rejects anything that is not a plain integer. bool is a subclass of int, so it is checked first.
def require_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")


#Computes base^exponent mod modulus without ever building the full power.
def modular_exponentiation(base, exponent, modulus):
    require_int(base, "base")
    require_int(exponent, "exponent")
    require_int(modulus, "modulus")
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    #1 % modulus makes modulus 1 return 0; reducing base also handles negative bases.
    result = 1 % modulus
    base = base % modulus

    #Each pass handles one binary digit of the exponent, lowest digit first.
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2

    return result
