import math
from fastModularExp import fastModularExponentation
from pkcs1.defaults import default_pseudo_random, default_crypto_random

#   n: Integer to be tested
#   a: random number
#   k fixed number of iterations http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
def millerRabin_2(n:int, a:int) -> bool :
    if a > n-2 or a < 2:
        print('MILLER RABIN: random a must be between 2 and n-2. FALSE')
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    # If s=1 then end the algorithm with message n is definitely not prime"
    if(s == 1):
        return False

    # Step 2
    # If X ≡ ±1(modn) Then end the algorithm with message "n is probably prime"
    x = fastModularExponentation(a, d, n)
    if x == 1 or x == n-1 :
        return True

    # If s=1 then end the algorithm with message n is definitely not prime"
    if(s == 1):
        return False

    # Step 3
    for r in range(1, s-1):
        x = fastModularExponentation(a, (2 ** r) * d, n)
        if x == 1:
            return False
        elif x == n-1 :
            return True
   
    # Step 5: r == s-1
    x = fastModularExponentation(a, (2 ** (s-1)) * d, n)
    
    return x == n-1



def millerRabin(e:int, p:int, a_random:int) -> bool:    
    #if((p).bit_length() != b):
       # return False
    return (millerRabin_2(p, a_random)) and  math.gcd( e, p-1 ) == 1


#primenumber = 953
#print(millerRabin_2(primenumber, random.randint(2, primenumber-2)))

