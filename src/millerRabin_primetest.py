from math import log2
import math
import random
from pkcs1 import primes,primitives
from fastModularExp import fastModularExponentation
from pkcs1.defaults import default_pseudo_random, default_crypto_random

#   n: Integer to be tested
#   a: random number
def millerRabin_2(n:int, a:int) -> bool :
    if a> n-2 or a<2:
        print('random a must be between 2 and n-2')

    #Step 1
    prev_n= n-1

    s = round(log2(prev_n))
    if s == 1 :
        return False
    d = prev_n // s 

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

def miller_rabin_3(n, k, rnd=default_pseudo_random):
    '''
       Pure python implementation of the Miller-Rabin algorithm.
       n - the integer number to test,
       k - the number of iteration, the probability of n being prime if the
       algorithm returns True is 1/2**k,
       rnd - a random generator
   '''
    s = 0
    d = n-1
    # Find nearest power of 2
    s = primitives.integer_bit_size(n)
    # Find greatest factor which is a power of 2
    s = math.gcd(2**s, n-1)
    d = (n-1) // s
    s = primitives.integer_bit_size(s) - 1
    while k:
        k = k - 1
        a = rnd.randint(2, n-2)
        x = pow(a,d,n)
        if x == 1 or x == n - 1:
            continue
        for r in range(1,s-1):
            x = pow(x,2,n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True

def millerRabin(e:int, p:int, a_random:int) -> bool:    
    #if((p).bit_length() != b):
       # return False
    return (millerRabin_2(p, a_random)) and  math.gcd( e, p-1 ) == 1


print(millerRabin_2(7, random.randint(2, 7-2)))
print(miller_rabin_3(7,1))