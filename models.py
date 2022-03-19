class pkgvr_output:
    def __init__(publicKeyRSA,privateKeyRSA):
        tuple(publicKeyRSA, privateKeyRSA)

class publicKeyRSA:    
    N=0
    e=0
    def __init__(self, N, e):
        self.e=e
        self.N=N

class privateKeyRSA:
    p=0
    q=0
    e=0
