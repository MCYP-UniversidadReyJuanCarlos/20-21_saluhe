from math import log2
from random import randint
def millerRabin(n:int) -> bool :
    #Step 1
    prev_n= n-1

    s = round(log2(prev_n))
    if s==1 :
        return False
    d = prev_n/s 

    # n - 1 must be even
    if(prev_n % 2 >0):
        return False

    #Step 2. (seed() function has not be called, so random function's seed is by default 1970)
    a = randint(2, n-2)   

    #Step 3.
    x= a^d % n
    aux = x % n
    if(aux == 1  or aux == -1):
        return True

    r=1
    #Step 4
    while True:
        x = a^((2^r)*d) % n
        if(x==1):
            return False
        elif(x==-1):
            return True
        
        r+=1
        if(r < s-1):
            break

    #Step 5: r == s-1
    x = a^((2^(s-1))*d) % n 
    if(x==-1):
        return True
    return False