
from Crypto.Random import random
from Crypto import Random
from Crypto.Util import number

#security 1^k = 1024 bits
class pedersen_commitment:
    g:any
    h:any
    q:any #g order
    
    def __init__(self):
        list = self.setup(1024)
        self.q=list[0]
        self.g=list[1]
        self.h=list[2]

    def setup(self, security)-> list:
        # Pick p, q primes such that p | q - 1, that is equvalent to
        # say that q = r*p + 1 for some r
        p = number.getPrime(security, Random.new().read)
        print("p = ",p)
        
        r = 1
        while True:
            q = r*p + 1
            if number.isPrime(q):
                print("q = ",q)
                break
            r += 1
        
        # Compute elements of G = {i^r mod q | i in Z_q*}
        G = set() 
        for i in range(1, q): # Z_q*
            G.add(i**r % q)

        G = list(G)
        print("Order of G = {i^r mod q | i in Z_q*} is " + str(len(G)) + " (must be equal to p).")
        
        # Since the order of G is prime, any element of G except 1 is a generator
        g = random.choice(list(filter(lambda e: e != 1, G)))
        print("g = ",g)
                
        h = random.choice(list(filter(lambda e: e != 1 and e != g, G)))
        print("h = ",h)
        
        # g and h are elements of G such that nobody knows math.log(h, g) (log of h base g)
            
        return [q,g,h]

    def open(self, g, q, h, c, m, r):    
        return c == (pow(g,m,q) * pow(h,r,q)) % q  

    def open(self, c, m, r):    
        return c == (pow(self.g,m,self.q) * pow(self.h,r,self.q)) % self.q  

    def commitment(self,g,q,h, m: int, r:int) -> any:
        #g^m mod q
        #Opening received = r
        return (pow(g,m,q) * pow(h,r,q)) % q
    
    def commitment(self, m: int, r:int) -> any:
        #Opening received = r
        return (pow(self.g,m,self.q) * pow(self.h,r,self.q)) % self.q