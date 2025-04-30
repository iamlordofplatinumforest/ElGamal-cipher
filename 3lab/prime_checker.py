import random
from typing import List


class PrimeChecker:
    def __init__(self, rounds: int = 5):
        self.rounds = rounds
    
    def is_prime(self, p: int) -> bool:
        if p < 2:
            return False
        if p == 2:
            return True
        if p % 2 == 0:
            return False
            
        d = p - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1

        for _ in range(self.rounds):
            a = random.randint(2, p - 2)
            x = pow(a, d, p)
            
            if x == 1 or x == p - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, p)
                if x == p - 1:
                    break
            else:
                return False
        return True
