#Public key generator with verifiable randomnes
import copy
import os
import sys
import threading
from time import gmtime, strftime
import time
from golberg import golberg_et_al
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

    #golberg     
    salt = univ.OctetString(os.urandom(32)) #Nist recommend salt string of at least 32 bit
    #HMAC(s',j+2,r_w)
    golberg = golberg_et_al(salt, s_prima, alg2_collection.a_collection.count + 2, e, r_w)
    proof_w = golberg.golberg(p,q)
    #----------------------------> send proof to CA
    if golberg.verify(salt, generate_hash(r_ca), alg2_collection.a_collection.count + 2, e, r_w, proof_w):
        asnPK= AsnPubKey()
        asnPK.setComponentByName('modulus',N) 
        asnPK.setComponentByName('publicExponent', e)
        return pkgvr_output(publicKeyRSA(N,e), privateKeyRSA(p,q,e))
    raise ValueError("golberg Proof: Not valid")


def writeOutputFile(s:str):
    lock_OutputFile.acquire()    
    outputFile.write(threading.current_thread().name+ ' ' + s + '\n')  
    lock_OutputFile.release()

def user():
    lock_InformationPipe.acquire()

    r_u = bytearray(mkNonce(),'ascii')
    writeOutputFile('r_u has been established: '+r_u.hex())  

    r_u_aux= copy.copy(r_u)
    # r'u=hash(0||ru)
    r_u[0:0] = int.to_bytes(0, 2, 'big')
    r_prima_u = generate_hash(r_u)

    r_u= copy.copy(r_u_aux)
    r_u_aux[0:0] = int.to_bytes(1, 2, 'big')
    p_u = generate_hash(r_u_aux)
    writeOutputFile('p_u has been established: '+p_u.hex())  

    r_u_aux= copy.copy(r_u)
    r_u[0:0] =int.to_bytes(2, 2, 'big')
    s_prima = generate_hash(r_u)
    writeOutputFile('Seed s_prima has been established: '+s_prima.hex())  

    #pedersen_commitment(r_prima_u,p_u)
    r_prima_u_asInteger=int.from_bytes(r_prima_u,'big')
    p_u_asInteger=int.from_bytes(p_u,'big')
    pedersen = pedersen_commitment()
    c = pedersen.commitment(r_prima_u_asInteger,p_u_asInteger)
    writeOutputFile('Commitment has been computed by pedersens scheme: '+str(c))  

    #----------------------------> send commitment to CA
    pipe.append(c)
    writeOutputFile('Commitment sent to CA --------->')  
    writeOutputFile('')
    lock_InformationPipe.release()
    time.sleep(2)

    #----------------------------> waiting r_ca
    lock_InformationPipe.acquire() 
    r_ca = pipe.pop()
    writeOutputFile('r_ca received from CA: '+r_ca.hex())

    s = xor(r_prima_u_asInteger, int.from_bytes(generate_hash(r_ca),'big'))
    writeOutputFile('Seed s has been established: ' + str(s))  

    #Algorithm 2
    hmac=hmac_class()
    alg2_collection:algorithm_2_output=algorithm_2(4, s, e, r_w, s_prima, hmac)
    if alg2_collection.i == -1 :
        raise ValueError("Algorithm 2: Impossible to get a valid collection of primes")

    #Set p, q and N
    p = alg2_collection.a_collection.pop(alg2_collection.i)
    writeOutputFile('Prime number p has been established: ' + str(p))  
    j = alg2_collection.a_collection.count
    q = alg2_collection.a_collection.pop(j)
    writeOutputFile(' Prime number q has been established: ' + str(q))
    N = p*q
    writeOutputFile('N has been established: ' + str(N)) 

    #golberg     
    salt = univ.OctetString(os.urandom(32)) #Nist recommend salt string of at least 32 bit
    #HMAC(s',j+2,r_w)
    golberg = golberg_et_al(salt, s_prima, alg2_collection.a_collection.count + 2, e, r_w)
    proof_w = golberg.golberg(p,q)
    
    pipe.append(q)
    pipe.append(p)
    pipe.append(alg2_collection.a_collection.count)
    pipe.append(proof_w)
    writeOutputFile('p, q, j and Proof sent to CA --------->')     
    writeOutputFile('')
    lock_InformationPipe.release()
    time.sleep(2)

    lock_InformationPipe.acquire()
    writeOutputFile('Proof received from CA') 

    if(pipe.pop()):
        lock_InformationPipe.release()
        outputFile.close()
        return pkgvr_output(publicKeyRSA(p*q ,e), privateKeyRSA(p, q, e))

    lock_InformationPipe.release()
    outputFile.close()
    raise ValueError("golberg Proof: Not valid")
   

def ca():    
    lock_InformationPipe.acquire()
    c = pipe.pop()
    writeOutputFile('Commitment received from user: ' + str(c))

    r_ca = bytearray(mkNonce(),'ascii') 
    writeOutputFile('r_ca has been established: '+ r_ca.hex()) 

    #----------------------------> send r_ca to user
    pipe.append(r_ca)
    writeOutputFile('r_ca sent to user --------->')
    writeOutputFile('')
    lock_InformationPipe.release()
    time.sleep(3)

    #----------------------------> waiting proof, N, j
    lock_InformationPipe.acquire()

    proof_w = pipe.pop()
    writeOutputFile('Proof from user: '+ proof_w)  
    j = pipe.pop()
    writeOutputFile('j from user: ' + str(j))  
    p = pipe.pop()
    writeOutputFile('p from user: ' + str(p))
    q = pipe.pop()
    writeOutputFile('p from user: ' + str(q)) 

    salt = univ.OctetString(os.urandom(32)) #Nist recommend salt string of at least 32 bit
    golberg =  golberg_et_al()
    if golberg.verify(salt, generate_hash(r_ca), j + 2, e, r_w, proof_w):
        asnPK= AsnPubKey()
        asnPK.setComponentByName('modulus', p*q) 
        asnPK.setComponentByName('publicExponent', e)
        
        pipe.append(True)
        writeOutputFile('golberg Proof: valid.')
        writeOutputFile('OK sent to user --------->')
        lock_InformationPipe.release()

        return asnPK
    
    writeOutputFile('golberg Proof: Not valid. Error sent to user --------->')
    pipe.append(False)
    lock_InformationPipe.release()

    raise ValueError("golberg Proof: Not valid")
        

#Threads
try:
    lock_OutputFile = threading.Lock()  #used to read/write in output file
    lock_InformationPipe = threading.Lock() #used to read/write in pipe structure

    pipe = []

    outputFilePath='Output_'+strftime('%Y-%m-%dT%H%M%SZ', gmtime())+'.txt'

    outputFile = open (outputFilePath,'a')
    outputFile.write('RSA Public-Key generation with verifiable randomness')
    outputFile.write('User and CA threads have been created')

    user_t = threading.Thread(name='USER Thread' , target = user)
    ca_t = threading.Thread(name='CA Thread' , target = ca)

    user_t.start()
    time.sleep(1)
    ca_t.start()
except:
    print('Main has finished with errors')
    outputFile.close()
    sys.exit()

#x= pkgvr()

    
