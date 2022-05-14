import math
import gmpy2

def fastModularExponentation(A:float, B:float, C:float):     
    if(B == -1):
        return gmpy2.invert(A, C)
    binB= numtobin(B)    
    Bdigits= len(binB) 
    AtoBmodC=[None]*Bdigits
    
    power=1
    product=0
    for i in range(0, Bdigits):
        if i == 0 :
            AtoBmodC[0]= mymod(A,C)        
        else:
            AtoBmodC[i]= mymod(AtoBmodC[i-1]*AtoBmodC[i-1],C)        
                 
        if binB[Bdigits-1-i] == "1" :
            if product == 0 :
                product= AtoBmodC[i]
            else:
                product *= AtoBmodC[i]
            
            product = mymod(product,C)
        
        power *=2
    
    result = mymod(product,C) 
    return result


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
