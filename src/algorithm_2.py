
from dodis_yampolsky import dodis_yampolsky
from hmac_c import hmac_class
from millerRabin_primetest import millerRabin

class algorithm_2_output:
    a_collection=[]
    i=0
    
#Input: 
#   T: number of iterations
#   s
#   e: fixed rsa exponent
#   k: security parameter
#   r_w: length bits
#   s_prima, r_w, hmac: params for random string HMAC(s', j, r_w)

#Returns:
#   A collection of values returned by Dodis-Yampolsky function. 
#   First index inside the previous collection that is supposed to be prime
def algorithm_2(T:int, s:int, e:any, k:int, s_prima:bytearray, hmac:hmac_class, r_w) -> algorithm_2_output:
    ctr=0
    j=0
    result:algorithm_2_output = algorithm_2_output()

    # Setup dodis and yampolsky prf
    prf=dodis_yampolsky()
    prf.gen(k)

    while (ctr<2 and j<T):
        j+=1
        aj = prf.sign_sk_provided(s,j)        
        result.a_collection.append(aj)

        # HMAC (1^rw, s',..)
        a_random = int.from_bytes(hmac.hmac_method(r_w, s_prima, int.to_bytes(j, r_w,'big')), 'big') 
        # B-bit long. gcd(e,(p-1))=1
        if millerRabin(e, aj, a_random):
            if ctr==0 :
                result.i=j
            ctr+=1  

    # Not valid
    if ctr<2:
        result.i=-1
        return result
    
    return result
   

