from typing import List, Tuple


class ElGamalCipher:
    def __init__(self):
        pass
    
    def encrypt(self, plaintext: bytes, p: int, g: int, y: int, k: int) -> List[Tuple[int, int]]:
        encrypted = []
        a = pow(g, k, p)
        
        for byte_val in plaintext:
            m = byte_val
            b = pow(y, k, p) * m % p
            encrypted.append((a, b))
            
        return encrypted
    
    def decrypt(self, encrypted: List[Tuple[int, int]], p: int, x: int) -> List[int]:
        decrypted = []
        
        for a, b in encrypted:
            s = pow(a, x, p)
            s_inv = pow(s, -1, p)
            m = (b * s_inv) % p
            decrypted.append(m)
            
        return decrypted
