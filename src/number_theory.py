import math
from typing import List


class NumberTheory:
    @staticmethod
    def find_prime_dividers(p: int) -> List[int]:
        dividers = []
        while p % 2 == 0:
            dividers.append(2)
            p //= 2
            
        for i in range(3, int(math.sqrt(p)) + 1, 2):
            while p % i == 0:
                dividers.append(i)
                p //= i
                
        if p > 2:
            dividers.append(p)
        return dividers
    
    @staticmethod
    def find_primitive_roots(p: int) -> List[int]:
        dividers = NumberTheory.find_prime_dividers(p - 1)
        roots = []
        
        for g in range(2, p):
            is_primitive_root = True
            for qi in dividers:
                temp = pow(g, (p - 1) // qi, p)
                if temp == 1:
                    is_primitive_root = False
                    break
            if is_primitive_root:
                roots.append(g)
        return roots
    
    @staticmethod
    def greatest_common_divisor(a: int, b: int) -> int:
        while b != 0:
            a, b = b, a % b
        return a
