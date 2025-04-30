from typing import Optional, List
from prime_checker import PrimeChecker
from key_generator import ElGamalKeyGenerator
from cipher import ElGamalCipher
from number_theory import NumberTheory


class CryptoParameters:
    def __init__(self):
        self.p: Optional[int] = None
        self.g: Optional[int] = None
        self.x: Optional[int] = None
        self.y: Optional[int] = None
        self.k: Optional[int] = None
        self.primitive_roots: List[int] = []
        
        self.prime_checker = PrimeChecker()
        self.key_generator = ElGamalKeyGenerator(self.prime_checker)
        self.cipher = ElGamalCipher()
    
    def set_prime(self, p: int) -> bool:
        if self.prime_checker.is_prime(p):
            self.p = p
            self.primitive_roots = NumberTheory.find_primitive_roots(p)
            return True
        return False
    
    def set_primitive_root(self, g: int) -> None:
        self.g = g
    
    def set_private_key(self, x: int) -> bool:
        if self.p and self.g and 1 < x < self.p - 1:
            self.x = x
            self.y = self.key_generator.calculate_public_key(self.p, x, self.g)
            return True
        return False
    
    def set_random_k(self, k: int) -> bool:
        if self.p:
            gcd = NumberTheory.greatest_common_divisor(k, self.p - 1)
            if gcd == 1:
                self.k = k
                return True
        return False
    
    def get_public_key_string(self) -> str:
        if self.p and self.g and self.y:
            return f"({self.p}, {self.g}, {self.y})"
        return ""
