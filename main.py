#Public key generator with verifiable randomnes
from datetime import datetime
from models import pkgvr_output
from hashSha256 import *
from operator import xor
from algorithm_2 import *
from pedersen import pedersen_commitment


def pkgvr(message: bytearray) -> pkgvr_output:
    r_u= bytearray(datetime.datetime.now)

    # r'u=hash(0||ru)
    r_prima_u= generate_hash(r_u.insert(0, int.to_bytes(0, 2, 'big')))
    p_u= generate_hash(r_u.insert(0, int.to_bytes(1, 2, 'big')))
    s_prima=generate_hash(r_u.insert(0, int.to_bytes(2, 2, 'big')))

    #pedersen_commitment(r_prima_u,p_u)
    pedersen = pedersen_commitment(r_prima_u,p_u)
    c = pedersen.commitment()
    #----------------------------> send commitment to CA


    #rca received
    r_ca= bytearray(datetime.datetime.now)
    s=xor(r_prima_u, r_ca)

    #Algorithm 2
    alg2_collection=algorithm_2(2, s)

    #Gelberg
    e=65537 #fixed rsa exponent
