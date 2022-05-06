# key  clave
# b block long 
import hashlib
from operator import xor
from typing import Hashable
from hashSha256 import generate_hash

class hmac_class:
    ipad=bytearray()
    opad=bytearray()

    def hmac_method(self, b:int, key:bytearray, text:bytearray) -> bytearray:
        k0=key
        self.define_defaultValues(b)

        #(L=16 for MD5, L=20 for SHA-1).
        #print('key parameter '+ k0.hex())
        if len(key) > b:
            #SHA-256(key) || 0
            k0 = bytearray(hashlib.new("sha1",key).digest())
            k0.extend(int.to_bytes(0, b - 20, 'big'))
        elif len(key) < b:    
            k0 = bytearray(k0)      
            k0.extend(int.to_bytes(0, b - len(key), 'big'))

        #Step 4
        k0_4 = bytearray(byte_xor(k0, self.ipad))
        #Step 5/Step 6
        k0_4.extend(text)
        k0_6=generate_hash(k0_4)
        #Step 7
        k0_7 = bytearray(byte_xor(k0, self.opad))
        print('k0_7 ' + k0_7.hex())
        
        k0_7.extend(k0_6)
        print('k0_7 || k0_6 ' + k0_7.hex())

        return generate_hash(k0_7)

    def define_defaultValues(self, b:int):
        self.ipad= bytearray(b'\x36'*b)
        self.opad= bytearray(b'\x5C'*b)
        #print(self.opad.hex())


def byte_xor(ba1, ba2):
    return bytes(a ^ b for (a, b) in zip(ba1, ba2))

