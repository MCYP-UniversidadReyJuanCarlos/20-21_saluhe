# Implementation of sieve of erastothenes algorithm in order to find all the prime numbers in a segment 1 -> n
def sieve_of_eratosthenes(n:int)-> list:
    candidates=[]
    result=set()
    visited =set()
    if(n<=1):
        return result
    for i in range(2,n+1):
        candidates.append(i)
    
    result.add(2)
    i=0 #Pointer to the next unmarked element 
    while(i < len(candidates)):
        for j in range(i+1, len(candidates)):
            #Delete those elements multiples of i and greater than or equal to the square of i
            if(candidates[j] % candidates[i] == 0 and candidates[j]  >= candidates[i]^2):
                visited.add(candidates[j])

                if candidates[j] in result :
                    result.discard(candidates[j])
                continue

            if candidates[j] not in visited:
                result.add(candidates[j])        
        i+=1
    return result

x= sieve_of_eratosthenes(10)