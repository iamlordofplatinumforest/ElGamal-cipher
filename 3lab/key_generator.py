import random
from typing import Tuple
from prime_checker import PrimeChecker


class ElGamalKeyGenerator:
    def __init__(self, prime_checker: PrimeChecker = None):
        self.prime_checker = prime_checker or PrimeChecker()
    
    def calculate_public_key(self, p: int, x: int, g: int) -> int:
        return pow(g, x, p)
    
    def generate_key_pair(self, p: int, g: int) -> Tuple[int, int]:
        x = random.randint(2, p - 2)
        y = self.calculate_public_key(p, x, g)
        return x, y
