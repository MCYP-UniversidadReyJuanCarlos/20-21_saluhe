#Public key generator with verifiable randomnes
import copy
import os
import threading
from time import gmtime, strftime
import time
from exception_text_to_file import Fill_OutputFile
from golberg import golberg_et_al, golberg_output
from models import privateKeyRSA, publicKeyRSA
from hashSha256 import *
from operator import xor
from algorithm_2 import *
from nonce import mkNonce
from pedersen import pedersen_commitment
from pyasn1.type import univ
from rsa.asn1 import AsnPubKey
from Crypto import Random
from Crypto.Util import number


e = 65537   # fixed rsa exponent
r_w = 256   # the RSA key length (bit-primes)
T = 600
k = 128     # security parameter for: Golberg / pedersen / Dodis-Yampolsky

# To generate RSA moduli which are products of two (b(λ)-bit) 1536-bit primes, the instantiation
# with the Dodis–Yampolskiy PRF uses l = 21535 + 554415 which is a Sophie Germain
# prime, Λ = (4l + 18)l + 1 and r = 1572 · Λ + 1.

def pkgvr() -> any:
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
    pedersen = pedersen_commitment(k)
    c = pedersen.commitment(r_prima_u_asInteger,p_u_asInteger)
    #----------------------------> send commitment to CA


    #rca received
    r_ca = bytearray(mkNonce(),'ascii')  
    s = xor(r_prima_u_asInteger, int.from_bytes(generate_hash(r_ca),'big'))

    #Algorithm 2
    hmac=hmac_class()
    alg2_collection:algorithm_2_output=algorithm_2(T, s, e, k, s_prima, hmac, r_w)
    if alg2_collection.i == -1 :
        output_connection.raise_exception(Exception("Algorithm 2: Impossible to get a valid collection of primes"))

    #Set p, q and N
    p = alg2_collection.a_collection.pop(alg2_collection.i)
    j = alg2_collection.a_collection.count
    q = alg2_collection.a_collection.pop(j)
    N = p*q

    #golberg     
    salt = univ.OctetString(os.urandom(32)) #Nist recommend salt string of at least 32 bit
    #HMAC(s',j+2,r_w)
    golberg = golberg_et_al(salt, s_prima, alg2_collection.a_collection.count + 2, e, r_w)
    proof_w = golberg.prove(p,q)
    #----------------------------> send proof to CA
    if golberg.verify(salt, generate_hash(r_ca), alg2_collection.a_collection.count + 2, e, r_w, proof_w):
        asnPK= AsnPubKey()
        asnPK.setComponentByName('modulus',N) 
        asnPK.setComponentByName('publicExponent', e)
        return (publicKeyRSA(N,e), privateKeyRSA(p,q,e))
    output_connection.raise_exception(Exception("golberg Proof: Not valid"))

def user():
    lock_InformationPipe.acquire()

    r_u = bytearray(mkNonce(),'ascii')
    output_connection.writeOutputFile('r_u has been established: '+r_u.hex())  

    r_u_aux= copy.copy(r_u)
    # r'u=hash(0||ru)
    r_u[0:0] = int.to_bytes(0, 2, 'big')
    r_prima_u = generate_hash(r_u)

    r_u= copy.copy(r_u_aux)
    r_u_aux[0:0] = int.to_bytes(1, 2, 'big')
    p_u = generate_hash(r_u_aux)
    output_connection.writeOutputFile('p_u has been established: '+p_u.hex())  

    r_u_aux= copy.copy(r_u)
    r_u[0:0] =int.to_bytes(2, 2, 'big')
    s_prima = generate_hash(r_u)
    output_connection.writeOutputFile('Seed s_prima has been established: '+s_prima.hex())  

    #pedersen_commitment(r_prima_u,p_u)
    r_prima_u_asInteger=int.from_bytes(r_prima_u,'big')
    p_u_asInteger=int.from_bytes(p_u,'big')
    pedersen = pedersen_commitment(r_w)
    c = pedersen.commitment(r_prima_u_asInteger,p_u_asInteger)
    output_connection.writeOutputFile('Commitment has been computed by pedersens scheme: '+str(c))  

    #----------------------------> send commitment to CA
    pipe.append(c)
    output_connection.writeOutputFile('Commitment sent to CA --------->')  
    output_connection.writeOutputFile('')
    lock_InformationPipe.release()
    time.sleep(2)

    #----------------------------> waiting r_ca
    lock_InformationPipe.acquire() 
    r_ca = pipe.pop()
    output_connection.writeOutputFile('r_ca received from CA: '+r_ca.hex())

    s = xor(r_prima_u_asInteger, int.from_bytes(generate_hash(r_ca),'big'))
    output_connection.writeOutputFile('Seed s has been established: ' + str(s))  

    #Algorithm 2
    hmac=hmac_class()
    alg2_collection:algorithm_2_output=algorithm_2(T, s, e, r_w, s_prima, hmac,r_w)
    if alg2_collection.i == -1 :
        output_connection.raise_exception(Exception("Algorithm 2: Impossible to get a valid collection of primes"))

    #Set p, q and N
    p = alg2_collection.a_collection.pop(alg2_collection.i - 1)
    output_connection.writeOutputFile('Prime number p has been established: ' + str(p))  
    j = len(alg2_collection.a_collection) - 1
    q = alg2_collection.a_collection.pop(j)
    output_connection.writeOutputFile(' Prime number q has been established: ' + str(q))
    N = p*q
    output_connection.writeOutputFile('N has been established: ' + str(N)) 


    # HMAC(s',j+2,r_w)
    hmac= hmac_class()   
    result_hmac= hmac.hmac_method(r_w, s_prima, int.to_bytes(j+2, r_w,'big'))
    aux = univ.OctetString.fromHexString(result_hmac.hex())
    # Nist recommend salt string of at least 32 bit
    salt = univ.OctetString(aux) 
    
    # alpha small prime  (about 16 bits long or less)
    alpha = number.getPrime(8, Random.new().read)
    
    golberg = golberg_et_al(salt, alpha, k, e, N.bit_length())
    proof_w = golberg.prove(p,q)
    
    pipe.append(golberg)
    pipe.append(proof_w)
	
    output_connection.writeOutputFile('Proof and systems parameter for Golberg proof sent to CA --------->')     
    output_connection.writeOutputFile('')
    lock_InformationPipe.release()
    time.sleep(2)

    lock_InformationPipe.acquire()
    output_connection.writeOutputFile('Proof verified from CA') 

    if(pipe.pop()):
        lock_InformationPipe.release()

        return (publicKeyRSA(p*q ,e), privateKeyRSA(p, q, e))

    lock_InformationPipe.release()    
    output_connection.raise_exception(Exception("golberg Proof: Not valid"))    

def ca():    
    lock_InformationPipe.acquire()
    c = pipe.pop()
    output_connection.writeOutputFile('Commitment received from user: ' + str(c))
	
    r_ca = bytearray(mkNonce(),'ascii') 
    output_connection.writeOutputFile('r_ca has been established: '+ r_ca.hex()) 

    #----------------------------> send r_ca to user
    pipe.append(r_ca)
    output_connection.writeOutputFile('r_ca sent to user --------->')
    output_connection.writeOutputFile('')
    lock_InformationPipe.release()
    time.sleep(3)

    #----------------------------> waiting proof, N, j
    lock_InformationPipe.acquire()

    proof_w:golberg_output = pipe.pop()
    golberg:golberg_et_al = pipe.pop()
    output_connection.writeOutputFile('Proof received from user')  

    if golberg.verify(proof_w):        
        pipe.append(True)
        output_connection.writeOutputFile('golberg Proof: valid.')
        output_connection.writeOutputFile('OK sent to user --------->')
        lock_InformationPipe.release()

        return proof_w.firstTuple

    output_connection.writeOutputFile('golberg Proof: Not valid. Error sent to user --------->')
    pipe.append(False)
    lock_InformationPipe.release()

    output_connection.raise_exception(Exception("golberg Proof: Not valid"))
       

def test_golberg():    
    lock_InformationPipe.acquire()
    r_u = bytearray(mkNonce(),'ascii')
    s_prima = generate_hash(r_u)
    p = number.getPrime(r_w, Random.new().read)    
    q = number.getPrime(r_w, Random.new().read)

    j = 2
    N = p*q
    output_connection.writeOutputFile('N has been established: ' + str(N)) 

    #HMAC(s',j+2,r_w)
    hmac= hmac_class()   
    result_hmac= hmac.hmac_method(r_w, s_prima, int.to_bytes(j+2, r_w,'big'))
    aux = univ.OctetString.fromHexString(result_hmac.hex())
    salt = univ.OctetString(aux) #Nist recommend salt string of at least 32 bit
    
    alpha = number.getPrime(8, Random.new().read) #alpha small prime α (about 16 bits long or less)
    golberg = golberg_et_al(salt, alpha, k, e, N.bit_length())
    proof_w = golberg.prove(p,q)
        
    pipe.append(golberg)
    pipe.append(proof_w)

    output_connection.writeOutputFile('Proof and systems parameter for Golberg proof sent to CA --------->')     
    output_connection.writeOutputFile('')
    lock_InformationPipe.release()
    time.sleep(2)

    lock_InformationPipe.acquire()
    output_connection.writeOutputFile('Proof verified from CA') 

    if(pipe.pop()):
        lock_InformationPipe.release()
        
        return (publicKeyRSA(p*q ,e), privateKeyRSA(p, q, e))

    lock_InformationPipe.release()    
    output_connection.raise_exception(Exception("golberg Proof: Not valid"))


def test_golberg_ca():
    lock_InformationPipe.acquire()
    r_ca = bytearray(mkNonce(),'ascii') 

    proof_w:golberg_output = pipe.pop()
    golberg:golberg_et_al = pipe.pop()
    output_connection.writeOutputFile('Proof received from user')  
    
    if golberg.verify(proof_w):
        
        pipe.append(True)
        output_connection.writeOutputFile('golberg Proof: valid.')
        output_connection.writeOutputFile('OK sent to user --------->')
        lock_InformationPipe.release()

        return proof_w.firstTuple
    
    output_connection.writeOutputFile('golberg Proof: Not valid. Error sent to user --------->')
    pipe.append(False)
    lock_InformationPipe.release()

    output_connection.raise_exception(Exception("golberg Proof: Not valid"))

#Threads
try:
    lock_OutputFile = threading.Lock()  #used to read/write in output file
    lock_InformationPipe = threading.Lock() #used to read/write in pipe structure

    pipe = []

    outputFilePath='Output_'+strftime('%Y-%m-%dT%H%M%SZ', gmtime())+'.txt'

    outputFile = open (outputFilePath,'a')
    output_connection = Fill_OutputFile(outputFile)
    outputFile.write('RSA Public-Key generation with verifiable randomness' + '\n')
    outputFile.write('User and CA threads have been created' + '\n')

    user_t = threading.Thread(name='USER Thread' , target = user)
    ca_t = threading.Thread(name='CA Thread' , target = ca)
   
    # These threads will end when main ends
    user_t.daemon = True
    ca_t.daemon = True

    user_t.start()   
    ca_t.start()

    user_t.join()
    outputFile.close()
    
except Exception as e:
    output_connection.raise_exception(e)




    
