from math import log2
import math
from random import randint

from fastModularExp import fastModularExponentation

def millerRabin_2(n:int, a:int) -> bool :
    if a> n-2 or a<2:
        print('random a must be between 2 and n-2')

    #Step 1
    prev_n= n-1

    s = round(log2(prev_n))
    if s==1 :
        return False
    d = int( prev_n / s )

    # n - 1 must be even
    if(prev_n % 2 >0):
        return False

    #Step 2. (seed() function has not be called, so random function's seed is by default 1970)  
    #Step 3.
    x = pow(a, d, n)
    aux = x % n
    if(aux == 1  or aux == -1):
        return True

    r=1
    #Step 4
    while True:
        x = fastModularExponentation(a, int((2^r)*d), n)
        if x == 1 :
            return False
        elif x == -1 :
            return True
        
        r+=1
        if(r < s-1):
            break

    #Step 5: r == s-1
    x = fastModularExponentation(a, int((2^(s-1))*d), n)
    if x == -1 :
        return True
    return False

def millerRabin(e:int, p:int, a_random:int) -> bool:    
    #if((p).bit_length() != b):
       # return False
    return (millerRabin_2(p, a_random)) and  math.gcd( e, p-1 ) == 1