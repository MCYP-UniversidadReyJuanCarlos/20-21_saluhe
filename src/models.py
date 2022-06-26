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
    def __init__(self, p, q, e):
        self.e=e
        self.p=p
        self.q=q
