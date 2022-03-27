# Implementation of sieve of erastothenes algorithm in order to find all the prime numbers in a segment 1 -> n
def sieve_of_eratosthenes(n:int)-> list:
    candidates=[]
    result:set={}

    for i in range(2,n+1):
        candidates.append(i)

    i=0 #Pointer to the next unmarked element   
    while(i < len(candidates)):
        for j in range(i, len(candidates)):
            #Delete those elements multiples of i and greater than or equal to the square of i
            if(j % i == 0 and j >= i^2):
                continue
            result.add(j)
        i+=1
    return result