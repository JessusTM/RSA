import random
import math


# ----- GENERACIÓN DE CLAVES -----
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
        raise ValueError(
            "Los números no son coprimos, por lo tanto, no existe el inverso modular"
        )
    else:
        return x % module


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
    try:
        prime1 = generateLargePrime(bitLength // 2)
        prime2 = generateLargePrime(bitLength // 2)
        module = prime1 * prime2
        phi = (prime1 - 1) * (prime2 - 1)
        publicExponent = 65537

        if gcd(publicExponent, phi) != 1:
            raise ValueError(
                f"El exponente público no es coprimo con φ(n). gcd({publicExponent}, {phi}) = {gcd(publicExponent, phi)}"
            )

        privateExponent = modularInverse(publicExponent, phi)
        return (module, publicExponent), (module, privateExponent), prime1, prime2

    except Exception as e:
        print(f"Error inesperado: {e}")
        raise


# ----- CIFRADO -----
def messageToNumber(message):
    number = 0
    for char in message:
        number = number * 256 + ord(char)
    return number


def modularExponentiation(base, exponent, module):
    result = 1
    base = base % module

    while exponent > 0:
        if exponent & 1:
            result = (result * base) % module

        exponent = exponent >> 1
        base = (base * base) % module

    return result


def encryptMessage(message, publicKey):
    module, publicExponent = publicKey
    messageNumber = messageToNumber(message)
    encryptedNumber = modularExponentiation(messageNumber, publicExponent, module)
    return encryptedNumber


# ----- DESCIFRADO -----
def numberToMessage(number):
    chars = []
    while number > 0:
        chars.append(chr(number % 256))
        number //= 256
    return "".join(reversed(chars))


def decryptMessage(encryptedNumber, privateKey):
    module, privateExponent = privateKey
    decryptedNumber = modularExponentiation(encryptedNumber, privateExponent, module)
    return numberToMessage(decryptedNumber)


def decryptChineseRemainder(ciphertext, privateExponent, primeP, primeQ):
    expModP = privateExponent % (primeP - 1)
    expModQ = privateExponent % (primeQ - 1)

    qInverseModP = modularInverse(primeQ, primeP)

    decryptP = modularExponentiation(ciphertext, expModP, primeP)
    decryptQ = modularExponentiation(ciphertext, expModQ, primeQ)

    difference = (decryptP - decryptQ) * qInverseModP % primeP
    decryptedMessage = decryptQ + difference * primeQ

    return numberToMessage(decryptedMessage)


# ----- MENÚ -----
def menu():
    try:
        print(" =============== RSA =============== ")
        mensaje = input("      Mensaje: ")

        print("\n   ---------- Claves ----------")
        publicKey, privateKey, primeP, primeQ = generateKeypair()
        print(f"    Clave pública: ({publicKey})")
        print(f"    Clave privada: ({privateKey})")

        print("\n   --------- Cifrado ----------")
        mensajeCifrado = encryptMessage(mensaje, publicKey)
        print(f"    Mensaje Cifrado: {mensajeCifrado}")

        print("\n   -------- Descifrado -------")
        mensajeDescifrado = decryptChineseRemainder(
            mensajeCifrado, privateKey[1], primeP, primeQ
        )
        print(f"    Mensaje Descifrado: {mensajeDescifrado}")

    except Exception as e:
        print(f"\nError: {e}")


menu()
