from asyncio.windows_events import NULL
from math import log2
import string
from typing import Counter
from pyasn1.type import univ

from asn1 import AsnPubKey
from hashSha256 import generate_hash

from models import publicKeyRSA

class gelberg_output:
    firstTuple:publicKeyRSA
    secondTuple=[]

class gelberg_key:
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

class gelberg_et_al:

    salt:string #Octet string
    alpha:int   #prime number
    k:int       #security parameter, 128
    e:int       #fixed prime RSA exponent
    len:int     #RSA key length

    def __init__(self, salt, alpha, k, e, len):
        self.salt=salt
        self.alpha=alpha
        self.k=k
        self.e=e
        self.len=len

    def gelberg(self, p:int, q:int) -> gelberg_output:
        #Step 1
        m1= int(abs( self.k/ (log2(self.alpha)) ))
        m2= int(abs( -self.k / ( log2( (1/self.alpha) + (1/self.e) * (1 - (1 / self.alpha)) ) ) ))

        #Step 2
        N=p*q

        #Step 3: get rsa key
        d_np= ((self.e*N)^-1) % (p-1)
        d_nq= ((self.e*N)^-1) % (q-1)

        k = gelberg_key(p,q, d_np, d_nq, q_inv)
        k_prima =gelberg_key(p,q, d_np, d_nq, q_inv)

        #Step 5        
        i=1
        result=gelberg_output()
        kRSA=publicKeyRSA(N,self.e)

        for i in range(1,m2):
            p_i= self.getRho(kRSA, self.salt, i, self.len, m2)
            if i <= m1:
                result.secondTuple.append(self.RSAPSP1(k_prima, p_i))
                continue
            result.secondTuple.append(self.RSAPSP1(k, p_i))

        return result

    #  m = [0..n-1], output [0..n-1]
    def RSAPSP1(k:gelberg_key, m) -> any :        
        if m in range(0, ):
            s_1 = (m^k.d_np) % k.p
            s_2 = (m^k.d_nq) % k.q
            n = ((s_1 - s_2)*k.q_inv) % k.p
            return s_2 + k.q * n
        return -1

    def getRho(self, keyPublic:publicKeyRSA, salt:string, i:int, len:int, m2:int) -> any :
        #Octet long of m2
        m2_long= abs((1/8) * (log2(m2+1)))

        j=1
        while(True):
            EI = self.I2OSP(i, m2_long)
            EJ = self.I2OSP(j, abs((1/8) * (log2(j+1))))
            s = pk.append(salt.append(EI.append(EJ)))
            ER = self.MGF1_SHA256(s,len)
            p_i = self.OS2IP(ER)
            if p_i>= keyPublic.N : 
                return p_i
            j+=1       

    def verify() :
        return

    # non negative integer to octet string
    def I2OSP(x:int, xLen:int):
        result=univ.OctetString('')
        if x < 256^xLen:
            i=1
            int_str= str(x)
            for i in range(1, xLen+1):
                #append 0
                if xLen-i > len(int_str):
                    result+= 0
                else: 
                    result+= int(int_str[xLen]) * (256 ^ (xLen-i))
            return result

        raise ValueError("integer too large")

    #   INPUT:  mgfSeed  seed from which mask is generated, an octet string
    #           maskLen  intended length in octets of the mask, at most 2^32 hLen
    # *hash length fixed in 256 (SHA-256)
    def MGF1_SHA256(self,mgfSeed:univ.OctetString, maskLen:int):
        hlen=256
        if maskLen > (2^32) * hlen :
            raise ValueError("mask too long")
        T= univ.OctetString('')
        for counter in range(0,maskLen//hlen):
            C = self.I2OSP(counter,4) # counter to octet string
            T += generate_hash(mgfSeed + C)

        return T

    # from octet string to int
    def OS2IP(X:univ.OctetString) -> int:
        result=0       
        for i in range(1, len(X)+1):
            result+= int(X[len(X)-i]) * (256 ^ (len(X)-i))
        return result