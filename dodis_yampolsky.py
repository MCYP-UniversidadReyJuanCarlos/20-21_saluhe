import math
from Crypto.Random import random
from Crypto import Random
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long

class dodis_yampolsky:
    sk:int
    pk:int
    g:any

    t:int # mod t

    def sign_sk(self,m:int):
        if m + self.sk == 0 :
            return 1
        return ((self.g % self.t) ** (1 / (m % self.t  + self.sk % self.t))) % self.t # g ^ 1/(x+sk)

    def sign_sk_provided(self,m:int, sk:int):
        if m + sk == 0 :
            return 1
        #return self.g ** (1 / (m + sk))       
        g = self.g % self.t
        x_sk= m % self.t + self.sk % self.t
        return ((self.g % self.t) ** (1 / (m % self.t  + self.sk % self.t))) % self.t

    #From a security parameter (k) obtain a generator g, sk, and pk
    def gen(self, k:int):
        # Pick p, q primes such that p | q - 1, that is equvalent to
        # say that q = r*p + 1 for some r
        #p is prime of length k

        p = number.getPrime(k)
        r = 1
        while True:
            q = r*p + 1
            if number.isPrime(q):
                break
            r += 1
        
        # Compute elements of G = {i^r mod q | i in Z_q*}
        G = [] 
        ctr=0
        self.t= q
        for i in range(1, q): # Z_q*
            aux=i**r % q
            if (aux!=1) :
                G.append(aux)
                ctr+=1
                if ctr==2:
                    break

        #G = list(set(G))
        
        # Since the order of G is prime, any element of G except 1 is a generator
        #self.g = random.choice(list(filter(lambda e: e != 1, G)))        
        #self.sk = random.choice(list(filter(lambda e: e != 1, G)))
        self.g = G[0]
        self.sk= G[1]

        # pk= g^s
        self.pk= self.g ^ self.sk
