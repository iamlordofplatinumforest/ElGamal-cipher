import random
import math

def isPrime(p): # Миллера-Рабина
    rounds = 5 # количество проверок с разными a
    # p - 1 = 2^r * d
    # d  нечетное, r - максимально возможная степень 2
    d = p - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for j in range(rounds):
        a = random.randint(2, p - 2)
        x = pow(a, d, p)
        # print(j, ") a= ", a, " x = ", x)
        if x == 1 or x == p - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, p)
            if x == p - 1:
                break
        else:
            return False
    return True

def findPrimeDividers(p):
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

def findPrimitiveRoots(p):
    dividers = findPrimeDividers(p - 1)
    roots = []
    for g in range(2, p):
        isPrimitiveRoot = True
        for qi in dividers:
            temp = pow(g, (p - 1) // qi, p)
            if temp == 1:
                isPrimitiveRoot = False
                break
        if isPrimitiveRoot:
            roots.append(g)
    return roots

def calculateY(p, x, g):
    return pow(g, x, p)

def greatestCommonDivisor(a, b): #алгоритм Евклида
    while b != 0:
        a, b = b, a % b
    return a

def ciphering(g, k, p, y, plaintext):
    encrypted = []
    a = pow(g, k, p)
    for char in plaintext:
        m = char
        b = pow(y, k, p) * m % p
        encrypted.append((a, b))
    return encrypted

def deciphering(p, x, encrypted):
    decrypted = []
    for a, b in encrypted:
        s = pow(a, x, p)
        s_inv = pow(s, -1, p)
        m = (b * s_inv) % p
        decrypted.append(m)
    return decrypted
