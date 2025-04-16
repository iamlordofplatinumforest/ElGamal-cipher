import random

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
        a = random.randrange(2, p - 2)
        x = pow(a, d, p)
        print(j, ") a= ", a, " x = ", x)
        if x == 1 or x == p - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, p)
            if x == p - 1:
                break
        else:
            return False
    return True

def simpleDividers(p):
   answer = []
   d = 2
   while d * d <= p:
       if p % d == 0:
           answer.append(d)
           p //= d
       else:
           d += 1
   if p > 1:
       answer.append(p)
   return answer