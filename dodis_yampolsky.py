from Crypto.Random import random
from Crypto import Random
from Crypto.Util import number

class dodis_yampolsky:
    sk:int
    pk:int
    g:any

    def sign_sk(self,m:int):
        if m + self.sk != 0 :
            return 1
        return self.g^(1 / (m + self.sk))

    def sign_sk_provided(self,m:int, sk:int):
        if m + sk != 0 :
            return 1
        return self.g^(1 / (m + sk))

    #From a security parameter (k) obtain a generator g, sk, and pk
    def gen(self, k:int, random_string:bytes):
        # Pick p, q primes such that p | q - 1, that is equvalent to
        # say that q = r*p + 1 for some r
        #p is prime of length k
        p = number.getPrime(k,random_string)
        r = 1
        while True:
            q = r*p + 1
            if number.isPrime(q):
                break
            r += 1
        
        # Compute elements of G = {i^r mod q | i in Z_q*}
        G = [] 
        for i in range(1, q): # Z_q*
            G.append(i**r % q)

        G = list(set(G))
        
        # Since the order of G is prime, any element of G except 1 is a generator
        self.g = random.choice(list(filter(lambda e: e != 1, G)))
        self.sk = random.choice(list(filter(lambda e: e != 1, G)))
        # pk= g^s
        self.pk= self.g ^ self.sk
