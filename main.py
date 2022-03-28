#Public key generator with verifiable randomnes
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
r_w=0       #the RSA key length

def pkgvr(message: bytearray) -> pkgvr_output:
    r_u = mkNonce()   

    # r'u=hash(0||ru)
    r_prima_u = generate_hash(r_u.insert(0, int.to_bytes(0, 2, 'big')))
    p_u = generate_hash(r_u.insert(0, int.to_bytes(1, 2, 'big')))
    s_prima = generate_hash(r_u.insert(0, int.to_bytes(2, 2, 'big')))

    #pedersen_commitment(r_prima_u,p_u)
    pedersen = pedersen_commitment(r_prima_u,p_u)
    c = pedersen.commitment()
    #----------------------------> send commitment to CA


    #rca received
    r_ca = mkNonce()
    s = xor(r_prima_u, generate_hash(r_ca))

    #Algorithm 2
    alg2_collection:algorithm_2_output=algorithm_2(2, s, e, r_w)
    if alg2_collection.i == -1 :
        raise ValueError("Algorithm 2: Impossible to get a valid collection of primes")

    #Set p, q and N
    p = alg2_collection.a_collection.pop(alg2_collection.i)
    q = alg2_collection.a_collection.pop(alg2_collection.a_collection.count)
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

    
