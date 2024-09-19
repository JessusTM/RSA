import random
import math


def gcd(a, b):
    return math.gcd(a, b)


def modularInverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return -1


def modularExponentiation(base, exponent, module):
    result = 1
    base = base % module

    while exponent > 0:
        if exponent & 1:
            result = (result * base) % module

        exponent = exponent >> 1
        base = (base * base) % module

    return result


def millerTest(oddComponent, numberToTest):
    randomBase = 2 + random.randint(1, numberToTest - 4)
    modResult = modularExponentiation(randomBase, oddComponent, numberToTest)

    if modResult == 1 or modResult == numberToTest - 1:
        return True

    while oddComponent != numberToTest - 1:
        modResult = (modResult * modResult) % numberToTest
        oddComponent *= 2

        if modResult == 1:
            return False

        if modResult == numberToTest - 1:
            return True

    return False


def isPrime(numberToTest, iterations):
    if numberToTest <= 1 or numberToTest == 4:
        return False
    if numberToTest <= 3:
        return True

    oddComponent = numberToTest - 1
    while oddComponent % 2 == 0:
        oddComponent //= 2

    for _ in range(iterations):
        if not millerTest(oddComponent, numberToTest):
            return False

    return True
