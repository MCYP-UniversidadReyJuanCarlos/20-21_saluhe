from random import randint
from Crypto import Random
from Crypto.Util import number

from fastModularExp import fastModularExponentation, mymod

#security 1^k = 1024 bits
class pedersen_commitment:
    g:any
    h:any
    q:any #g order
    
    def __init__(self, k):
        list = self.setup(k)
        self.q=list[0]
        self.g=list[1]
        self.h=list[2]

    def setup(self, security)-> list:
        # Pick p, q primes such that p | q - 1, that is equvalent to
        # say that q = r*p + 1 for some r
        p = number.getPrime(security, Random.new().read)
        print("PEDERSEN. p = ",p)
        
        r = 1
        while True:
            q = r*p + 1
            if number.isPrime(q):
                print("PEDERSEN. q = ",q)
                break
            r += 1
        
        # Compute elements of G = {i^r mod q | i in Z_q*}
        G = [] 
        last_i=0
        ctr_i = 0
        for i in range(1,q):
            i = randint(2,q)
            if i!=last_i:
                aux = i**r % q # Z_q*
                if aux!=1 :
                    G.append(aux)
                    last_i = i
                    ctr_i += 1
                    if ctr_i == 2:
                        break

        # Since the order of G is prime, any element of G except 1 is a generator
        g = G[0]
        print("PEDERSEN. g = ",g)
                
        h = G[1]
        print("PEDERSEN. h = ",h)
        
        # g and h are elements of G such that nobody knows math.log(h, g) (log of h base g)
            
        return [q,g,h]

    def open(self, g, q, h, c, m, r):    
        return c == mymod(fastModularExponentation(g,m,q) * fastModularExponentation(h,r,q), q)

    def open(self, c, m, r):    
        return c == mymod(fastModularExponentation(self.g,m,self.q) * fastModularExponentation(self.h,r,self.q), self.q )

    def commitment(self,g,q,h, m: int, r:int) -> any:
        #g^m mod q
        #Opening received = r
        return mymod((fastModularExponentation(g,m,q) * fastModularExponentation(h,r,q)), q)
    
    def commitment(self, m: int, r:int) -> any:
        #Opening received = r
        return mymod(fastModularExponentation(self.g,m,self.q) * fastModularExponentation(self.h,r,self.q), self.q)