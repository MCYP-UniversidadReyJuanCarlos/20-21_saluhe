#Public key generator with verifiable randomnes
import copy
import os
from gelberg import gelberg_et_al
from models import pkgvr_output, privateKeyRSA, publicKeyRSA
from hashSha256 import *
from operator import xor
from algorithm_2 import *
from nonce import mkNonce
from pedersen import pedersen_commitment
from pyasn1.type import univ
from rsa.asn1 import AsnPubKey


e = 65537   #fixed rsa exponent
r_w = 1536    #the RSA key length (bit-primes)

# To generate RSA moduli which are products of two (b(λ)-bit) 1536-bit primes, the instantiation
# with the Dodis–Yampolskiy PRF uses l = 21535 + 554415 which is a Sophie Germain
# prime, Λ = (4l + 18)l + 1 and r = 1572 · Λ + 1.

def pkgvr() -> pkgvr_output:
    r_u = bytearray(mkNonce(),'ascii')  

    r_u_aux= copy.copy(r_u)
    # r'u=hash(0||ru)
    r_u[0:0] = int.to_bytes(0, 2, 'big')
    r_prima_u = generate_hash(r_u)

    r_u= copy.copy(r_u_aux)
    r_u_aux[0:0] = int.to_bytes(1, 2, 'big')
    p_u = generate_hash(r_u_aux)

    r_u_aux= copy.copy(r_u)
    r_u[0:0] =int.to_bytes(2, 2, 'big')
    s_prima = generate_hash(r_u)

    #pedersen_commitment(r_prima_u,p_u)
    r_prima_u_asInteger=int.from_bytes(r_prima_u,'big')
    p_u_asInteger=int.from_bytes(p_u,'big')
    pedersen = pedersen_commitment()
    c = pedersen.commitment(r_prima_u_asInteger,p_u_asInteger)
    #----------------------------> send commitment to CA


    #rca received
    r_ca = bytearray(mkNonce(),'ascii')  
    s = xor(r_prima_u_asInteger, int.from_bytes(generate_hash(r_ca),'big'))

    #Algorithm 2
    hmac=hmac_class()
    alg2_collection:algorithm_2_output=algorithm_2(4, s, e, r_w, s_prima, hmac)
    if alg2_collection.i == -1 :
        raise ValueError("Algorithm 2: Impossible to get a valid collection of primes")

    #Set p, q and N
    p = alg2_collection.a_collection.pop(alg2_collection.i)
    j = alg2_collection.a_collection.count
    q = alg2_collection.a_collection.pop(j)
    N = p*q

    #Gelberg     
    salt = univ.OctetString(os.urandom(32)) #Nist recommend salt string of at least 32 bit
    #HMAC(s',j+2,r_w)
    gelberg = gelberg_et_al(salt, s_prima, alg2_collection.a_collection.count + 2, e, r_w)
    proof_w = gelberg.gelberg(p,q)
    #----------------------------> send proof to CA
    if gelberg.verify(salt, generate_hash(r_ca), alg2_collection.a_collection.count + 2, e, r_w,proof_w):
        asnPK= AsnPubKey()
        asnPK.setComponentByName('modulus',N) 
        asnPK.setComponentByName('publicExponent', e)
        return pkgvr_output(publicKeyRSA(N,e), privateKeyRSA(p,q,e))
    raise ValueError("Gelberg Proof: Not valid")




x= pkgvr()

    
