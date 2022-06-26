import math
import gmpy2

# converts a non-negative integer to 
# binary represented by a string of 1s and 0s 
def numtobin(num):
    bintext=""
    bits = math.floor(math.log(num) / math.log(2)) +1
    currentnum=num
    for i in range(0,bits):
        bintext = str(currentnum % 2) + bintext
        currentnum = math.floor(currentnum/2)
    
    return bintext


# converts a binary number (represented by a string of 1s 
# and 0s) to a non-negative integer 
def bintonum(binchars):
    binnum=0
    multiplier=1
    for i in range(0,binchars):
        if binchars[len(binchars)-i-1] == "1":
            binnum += 1*multiplier    
        
        multiplier*=2
    
    return binnum


#calculates A mod B (using quotient remainder theorem)
def mymod(A,B):
    # A=B*Q+R, where  0 <= R < B
    # A mod B = R
    # R= A-B*Q, Q=floor(A/B)
    return A - math.floor(A // B)*B #  use // to get an integer back from the division of the two integers

# A^B MOD C
def fastModularExponentation(base:int, exponent:int, modulus:int) :
    r = 1
    b = mymod(base, modulus)
    if b == 0 :
        return 0
    while exponent > 0:
        #Odd number
        if mymod(exponent, 2) != 0:
            r = mymod((r * b), modulus)
        exponent = exponent // 2
        b = mymod((b ** 2), modulus)
    
    return r
    
