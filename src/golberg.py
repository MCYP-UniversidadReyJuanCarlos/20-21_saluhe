from asyncio.windows_events import NULL
from math import log2
import math
from pyasn1.type import univ
from fastModularExp import fastModularExponentation, mymod
from hashSha256 import generate_hash
from millerRabin_primetest import millerRabin
from rsa.asn1 import AsnPubKey
from pyasn1.codec.der import encoder
from Crypto.Util.number import ceil_div
from sieve_of_eratosthenes import sieve_of_eratosthenes
import gmpy2
from pkcs1 import primitives
from Crypto.Util import number

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
        self.len=len    #Length in bits RSA modulus(N)

    def prove(self, p:int, q:int) -> golberg_output:
        try:
            #Step 1
            m1 = math.ceil( self.k / (log2(self.alpha)) )
            m2 = math.ceil( -self.k / ( log2( (1/self.alpha) + (1/self.e) * (1 - (1 / self.alpha)) ) ) )

            #Step 2
            N = p*q
            
            #Step 3: get rsa key
            q_inv = gmpy2.invert(q, p) #qInv = (inverse of q) mod p
            d_np = gmpy2.invert(self.e, p-1) #e^-1 mod p-1
            d_nq = gmpy2.invert(self.e, q-1) #e^-1 mod q-1
            k = golberg_key(p, q, d_np, d_nq, q_inv)

            d_np_prima = gmpy2.invert(self.e*N, p-1) #eN^-1 mod p-1
            d_nq_prima = gmpy2.invert(self.e*N, q-1) #eN^-1 mod q-1
            k_prima = golberg_key(p, q, d_np_prima, d_nq_prima, q_inv)

            #Step 5        
            i=1
            result=golberg_output()
            asnKRSA= AsnPubKey()
            asnKRSA.setComponentByName('modulus', N) 
            asnKRSA.setComponentByName('publicExponent', self.e)
            result.firstTuple = asnKRSA

            for i in range(1, m2+1):
                p_i = self.getRho(asnKRSA, self.salt, i, self.len, m2)
                if p_i not in range(0, N-1):
                    raise ValueError("Golberg: Message representative out of range")
                if i <= m1:                
                    result.secondTuple.append(self.RSASP1(k_prima, p_i))
                    continue
                
                result.secondTuple.append(self.RSASP1(k, p_i))

            return result
        except Exception as e:
            raise e

    #  m = [0..n-1], output [0..n-1]
    def RSASP1(self,k:golberg_key, m) -> any : 
        #Second form of the key. Step 2      
        
        s_1 = fastModularExponentation(m, k.d_np, k.p)
        s_2 = fastModularExponentation(m, k.d_nq, k.q)
        h = mymod((s_1 - s_2) * k.q_inv, k.p)

        return s_2 + k.q * h

    def getRho(self, asnPK:AsnPubKey, salt:univ.OctetString, i:int, len:int, m2:int) -> any :
        #Octet long of m2
        m2_long= abs(math.ceil( (1/8) * (log2(m2+1)) ))

        # PK ASN.1 octet string encoding of the RSA public key (N, e)
        pk_encoded = encoder.encode(asnPK)
        # Returns DER encoded octet stream
        PK = univ.OctetString(pk_encoded)
        
        # EI= I2OSP(i, |m2|) be the |m2|-octet long string encoding of the integer i
        EI = univ.OctetString(primitives.i2osp(i, m2_long))

        j=1
        while(True):
            EJ =  univ.OctetString(primitives.i2osp(j, abs(math.ceil((1/8) * (log2(j+1))))))
            result_concat = strFromOctetString(PK) + strFromOctetString(salt) + strFromOctetString(EI) + strFromOctetString(EJ)
            
            s = univ.OctetString(result_concat)
            ER = self.MGF1_SHA256(s, len)
            p_i= primitives.os2ip(ER.asOctets())

            #This step tests if p_i in Z_N
            if p_i < asnPK.getComponentByName("modulus") : 
                return p_i
            j += 1       

    # non negative integer to octet string. 
    # Most significant at the beginning
    def I2OSP(self, x:int, xLen:int) -> univ.OctetString:
        result = list()
        if x < 256**xLen:
            i = 1
            int_str = str(x)
            for i in range(1, xLen+1):
                #append 0
                if xLen-i >= len(int_str):
                    result.append(0)
                else: 
                    result.append(int(int_str[xLen-i]) * (256 ** (xLen-i)))
                    
            numberAsTuple = tuple(result)            
            return univ.OctetString(numberAsTuple)

        raise ValueError("integer too large")

    #   INPUT:  mgfSeed  seed from which mask is generated, an octet string
    #           maskLen  intended length in octets of the mask, at most 2^32 hLen
    # *hash length fixed in 256 (SHA-256)
    def MGF1_SHA256(self, mgfSeed:univ.OctetString, maskLen:int):
        hlen = 256 // 8 #in octets

        maskLen //= 8
        if maskLen > (2**32) * hlen :
            raise ValueError("mask too long")
        T = str('')
        
        long = ceil_div(maskLen, hlen)
        for counter in range(0, long):
            C =  univ.OctetString(primitives.i2osp(counter, 4)) # counter to octet string
            concatOctetStr = strFromOctetString(mgfSeed) + strFromOctetString(C)
            hashT = generate_hash(concatOctetStr.encode(mgfSeed.encoding))
            T += hashT.hex() #T = T || Hash(mgfSeed || C)

        return univ.OctetString(univ.OctetString.fromHexString(T))

    

    # from octet string to int
    def OS2IP(self, X:univ.OctetString) -> int:
        result = 0 
        xAsString = X.asNumbers()   
        xLen = len(xAsString)
        for i in range(1, xLen+1):
            x_elem = xAsString[xLen-i]
            result += int(x_elem) * (256 ** (xLen-i))
        return result


    def verify(self, info:golberg_output) -> bool:
        if info != NULL and info.firstTuple != NULL and info.firstTuple.getComponentByName('modulus') >= 2 ** (self.len - 1):

            if number.isPrime(self.e):
                #Set m1, m2
                m1 = math.ceil( self.k / (log2(self.alpha)) )
                m2 = math.ceil( -self.k / ( log2( (1/self.alpha) + (1/self.e) * (1 - (1 / self.alpha)) ) ) )

                if info.secondTuple!= NULL and len(info.secondTuple) == m2:
                    #Primes vector that included all primes numbers <= alpha-1
                    primes_vector = sieve_of_eratosthenes(self.alpha-1)

                    if math.gcd(primorial(primes_vector),
                        info.firstTuple.getComponentByName('modulus')) == 1 :

                        weird_key = AsnPubKey()
                        weird_key.setComponentByName('modulus', info.firstTuple.getComponentByName('modulus'))
                        weird_key.setComponentByName('publicExponent', info.firstTuple.getComponentByName('publicExponent') * info.firstTuple.getComponentByName('modulus'))
                        
                        for i in range(1, m2+1):
                            pi = self.getRho(info.firstTuple, self.salt, i, self.len, m2)
                            
                            if i <= m1 and pi != self.RSAVP1(weird_key, info.secondTuple[i-1]):
                                #ρi = RSAVP1((N, eN), σi)
                                return False                             
                            elif pi != self.RSAVP1(info.firstTuple, info.secondTuple[i-1]):
                                #ρi = RSAVP1(PK , σi)
                                return False
                        return True                               

        return False
        
    # Input
    #   (n, e) RSA public key
    #   s signature representative, an integer between 0 and n - 1  
    # Output:
    #   m message representative, an integer between 0 and n - 1
    def RSAVP1(self, key:AsnPubKey, s:int)-> int:
        #If the signature representative s is not between 0 and n - 1, output "signature representative out of range" and stop.
        if s < 0 or s >= key.getComponentByName('modulus'):
            raise ValueError("signature representative out of range")
        
        #Step 2
        m = fastModularExponentation(s, key.getComponentByName('publicExponent'), key.getComponentByName('modulus'))
        return m


#Input
#   vector: int collection
#Output
#   product of elements inside input collection
def primorial(vector:any)-> int:
    result=1
    for a in vector:
        result*=a
    return result

def strFromOctetString(mgfSeed:univ.OctetString) -> str:
        return mgfSeed.asOctets().decode(mgfSeed.encoding)


