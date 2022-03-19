
from dodis_yampolsky import dodis_yampolsky
from millerRabin_primetest import millerRabin


class algorithm_2_output:
    a_collection=[]
    i=0
    
    #Input: T, s
    #Returns:
    #   A collection of values returned by Dodis function. 
    #   First index inside the previous collection that is supposed to be prime
def algorithm_2(T:int,s:int) -> algorithm_2_output:
    ctr,i,j=0
    result:algorithm_2_output = algorithm_2_output()
    while (ctr<2 and j<T):
        j+=1
        aj = dodis_yampolsky(s,j)
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
   

