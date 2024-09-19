import random
import math


def gcd(a, b):
    return math.gcd(a, b)


def extendedGcd(number1, number2):
    if number1 == 0:
        return (number2, 0, 1)
    else:
        gcd, x1, y1 = extendedGcd(number2 % number1, number1)
        return (gcd, y1 - (number2 // number1) * x1, x1)


def modularInverse(number, module):
    gcd, x, y = extendedGcd(number, module)
    if gcd != 1:
        print("Los números no son coprimos, por lo tanto, no existe el inverso modular")
        return None
    else:
        return x % module


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


def generateLargePrime(bitLength):
    while True:
        primeCandidate = random.getrandbits(bitLength)
        primeCandidate |= (1 << bitLength - 1) | 1
        if isPrime(primeCandidate, 40):
            return primeCandidate


def generateKeypair(bitLength=1024):
    prime1 = generateLargePrime(bitLength // 2)
    prime2 = generateLargePrime(bitLength // 2)
    modulus = prime1 * prime2
    phi = (prime1 - 1) * (prime2 - 1)

    publicExponent = 65537
    if gcd(publicExponent, phi) != 1:
        print("El exponente público no es coprimo con φ(n)")
        return None

    privateExponent = modularInverse(publicExponent, phi)

    if privateExponent is None:
        print("No se pudo calcular el inverso modular")
        return None

    return ((modulus, publicExponent), (modulus, privateExponent))
