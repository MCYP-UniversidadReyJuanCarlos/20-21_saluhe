
from dodis_yampolsky import dodis_yampolsky
from millerRabin_primetest import millerRabin


class algorithm_2_output:
    a_collection=[]
    i=0
    
    #Input: 
    #   T: number of iterations
    #   s
    #   e: fixed rsa exponent
    #   b: length bits
    #Returns:
    #   A collection of values returned by Dodis-Yampolsky function. 
    #   First index inside the previous collection that is supposed to be prime
def algorithm_2(T:int,s:int, k:int, e:any, b:int) -> algorithm_2_output:
    ctr,i,j=0
    result:algorithm_2_output = algorithm_2_output()

    #Setup dodis and yampolsky prf 
    prf=dodis_yampolsky()
    prf.gen(k)

    while (ctr<2 and j<T):
        j+=1
        aj = prf.sign_sk_provided(s,j)
        result.a_collection.insert(aj)

        if millerRabin(b, e, aj):
            if(ctr==0):
                result.i=j
            ctr+=1  

    #Not valid
    if ctr<2:
        result.i=-1
        return result
    
    return result
   

