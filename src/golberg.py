from asyncio.windows_events import NULL
from math import log2
import math
import string
from pyasn1.type import univ
from euclidesAlgorithm import euclidesAlgorithm
from fastModularExp import fastModularExponentation
from hashSha256 import generate_hash
from millerRabin_primetest import millerRabin
from rsa.asn1 import AsnPubKey
from pyasn1.codec.der import encoder
from Crypto.Util.number import ceil_div
from models import publicKeyRSA
from sieve_of_eratosthenes import sieve_of_eratosthenes

class golberg_output:
    firstTuple:AsnPubKey
    secondTuple=[]

class golberg_key:
    p:int
    q:int
    d_np:int
    d_nq:int
    q_inv:int

    def __init__(self, p, q, d_np, d_nq, q_I):
        self.d_nq=d_nq
        self.q=q
        self.p=p
        self.d_np=d_np
        self.q_inv=q_I

class golberg_et_al:

    salt:univ.OctetString   #Octet string
    alpha:int               #prime number
    k:int                   #security parameter, 128
    e:int                   #fixed prime RSA exponent
    len:int                 #RSA key length

    def __init__(self, salt, alpha, k, e, len):
        self.salt=salt
        self.alpha=alpha
        self.k=k
        self.e=e
        self.len=len    

    def golberg(self, p:int, q:int) -> golberg_output:
        #Step 1
        m1= int(abs( self.k / (log2(self.alpha)) ))
        m2= int(abs( -self.k / ( log2( (1/self.alpha) + (1/self.e) * (1 - (1 / self.alpha)) ) ) ))

        #Step 2
        N = p*q

        #Step 3: get rsa key
        d_np = euclidesAlgorithm(self.e*N, -1, p-1)
        d_nq = euclidesAlgorithm(self.e*N, -1, q-1)
        #qInv = (inverse of q) mod p
        q_inv = euclidesAlgorithm(q, -1, p)

        k = golberg_key(p,q, d_np, d_nq, q_inv)
        k_prima = golberg_key(p,q, d_np, d_nq, q_inv)

        #Step 5        
        i=1
        result=golberg_output()
        asnKRSA= AsnPubKey()
        asnKRSA.setComponentByName('modulus', N) 
        asnKRSA.setComponentByName('publicExponent', self.e)
        for i in range(1,m2+1):
            p_i = self.getRho(asnKRSA, self.salt, i, self.len, m2)
            if p_i not in range(0, N-1):
                raise ValueError("Golberg: Message representative out of range")
            if i <= m1:                
                result.secondTuple.append(self.RSASP1(k_prima, p_i))
                continue
            
            result.secondTuple.append(self.RSASP1(k, p_i))

        return result

    #  m = [0..n-1], output [0..n-1]
    def RSASP1(k:golberg_key, m) -> any : 
        #Second form of the key. Step 2      
        
        s_1 = fastModularExponentation(m, k.d_np, k.p)
        s_2 = fastModularExponentation(m, k.d_nq, k.q)
        h = ((s_1 - s_2) * k.q_inv) % k.p

        return s_2 + k.q * h

    def getRho(self, asnPK:AsnPubKey, salt:string, i:int, len:int, m2:int) -> any :
        #Octet long of m2
        m2_long= abs((1/8) * (log2(m2+1)))

        #PK ASN.1 octet string encoding of the RSA public key (N, e)
        PK = univ.OctetString(encoder.encode(asnPK))
        #EI= I2OSP(i, |m2|) be the |m2|-octet long string encoding of the integer i
        EI = self.I2OSP(i, m2_long)

        j=1
        while(True):
            EJ = self.I2OSP(j, abs((1/8) * (log2(j+1))))
            s = PK.append(salt.append(EI.append(EJ)))
            ER = self.MGF1_SHA256(s, len)
            p_i = self.OS2IP(ER)

            #This step tests if p_i in Z_N
            if p_i < asnPK.N : 
                return p_i
            j += 1       

    # non negative integer to octet string
    def I2OSP(x:int, xLen:int):
        result=univ.OctetString('')
        if x < 256**xLen:
            i = 1
            int_str = str(x)
            for i in range(1, xLen+1):
                #append 0
                if xLen-i > len(int_str):
                    result += 0
                else: 
                    result += int(int_str[xLen]) * (256 ** (xLen-i))
            return result

        raise ValueError("integer too large")

    #   INPUT:  mgfSeed  seed from which mask is generated, an octet string
    #           maskLen  intended length in octets of the mask, at most 2^32 hLen
    # *hash length fixed in 256 (SHA-256)
    def MGF1_SHA256(self, mgfSeed:univ.OctetString, maskLen:int):
        hlen = 256
        if maskLen > (2**32) * hlen :
            raise ValueError("mask too long")
        T = univ.OctetString('')

        long = ceil_div(maskLen, hlen)
        for counter in range(0, long):
            C = self.I2OSP(counter, 4) # counter to octet string
            T += generate_hash(mgfSeed + C)

        return T

    # from octet string to int
    def OS2IP(X:univ.OctetString) -> int:
        result = 0       
        for i in range(1, len(X)+1):
            result += int(X[len(X)-i]) * (256 ** (len(X)-i))
        return result

    def verify(self,salt, alpha, k, e, len, info:golberg_output) -> bool:
        if info != NULL and info.firstTuple != NULL and info.firstTuple.getComponentByName('modulus') >= 2 ** (len-1):

            if millerRabin(e):
                #Set m1, m2
                m1= int(abs( k/ (log2(alpha)) ))
                m2= int(abs( k / ( log2( (1/alpha) + (1/e) * (1 - (1 / alpha)) ) ) ))

                if info.secondTuple!= NULL and info.secondTuple.count == m2:
                    #Primes vector that included all primes numbers <= alpha-1
                    primes_vector = sieve_of_eratosthenes(alpha-1)

                    if math.gcd(primorial(primes_vector),
                        info.firstTuple.getComponentByName('modulus')) == 1 :

                        weird_key = AsnPubKey()
                        weird_key.setComponentByName('modulus', info.firstTuple.getComponentByName('modulus'))
                        weird_key.setComponentByName('publicExponent', e * info.firstTuple.getComponentByName('modulus'))
                        
                        for i in range(0,m2):
                            pi=self.getRho(info.firstTuple, salt, i+1,len,m2)
                            
                            if i<=m1 and pi!=self.RSAVP1(weird_key, info.secondTuple[i]):
                                #ρi = RSAVP1((N, eN), σi)
                                return False                             
                            elif pi!=self.RSAVP1(info.firstTuple, info.secondTuple[i]):
                                #ρi = RSAVP1(PK , σi)
                                return False
                        return True                               

        return False
        
    # Input
    #   (n, e) RSA public key
    #   s signature representative, an integer between 0 and n - 1  
    # Output:
    #   m message representative, an integer between 0 and n - 1
    def RSAVP1(key:AsnPubKey, s:int)-> int:
        if s<0 or s >  key.getComponentByName('modulus')-1:
            raise ValueError("signature representative out of range")
        return (s**key.getComponentByName('publicExponent')) %  key.getComponentByName('modulus')


#Input
#   vector: int collection
#Output
#   product of elements inside input collection
def primorial(vector:any)-> int:
    result=1
    for a in vector:
        result*=a
    return result
