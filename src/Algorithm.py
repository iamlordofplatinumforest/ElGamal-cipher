from prime_checker import PrimeChecker
from number_theory import NumberTheory
from key_generator import ElGamalKeyGenerator
from cipher import ElGamalCipher


def isPrime(p):
    checker = PrimeChecker()
    return checker.is_prime(p)

def findPrimeDividers(p):
    return NumberTheory.find_prime_dividers(p)

def findPrimitiveRoots(p):
    return NumberTheory.find_primitive_roots(p)

def calculateY(p, x, g):
    generator = ElGamalKeyGenerator()
    return generator.calculate_public_key(p, x, g)

def greatestCommonDivisor(a, b):
    return NumberTheory.greatest_common_divisor(a, b)

def ciphering(g, k, p, y, plaintext):
    cipher = ElGamalCipher()
    return cipher.encrypt(plaintext, p, g, y, k)

def deciphering(p, x, encrypted):
    cipher = ElGamalCipher()
    return cipher.decrypt(encrypted, p, x)