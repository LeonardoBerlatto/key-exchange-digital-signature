package org.example.rsa

import org.example.utils.PrimeGenerator
import java.math.BigInteger
import java.security.SecureRandom


fun generateKeyPair(): Pair<PublicKey, PrivateKey> {
    val firstPrime = PrimeGenerator.generatePrime()
    val secondPrime = PrimeGenerator.generatePrime()

    val modulus = getSystemModulus(firstPrime, secondPrime)

    val eulerFunctionValue = computeEulerFunction(firstPrime, secondPrime)

    val publicKey = PublicKey(
        computePublicKey(eulerFunctionValue),
        modulus
    )
    val privateKey = PrivateKey(
        computePrivateKey(publicKey.exponent, eulerFunctionValue),
        modulus
    )

    return Pair(publicKey, privateKey)
}

private fun computePrivateKey(publicKey: BigInteger, eulerFunction: BigInteger) =
    publicKey.modInverse(eulerFunction)


private fun computePublicKey(phiValue: BigInteger): BigInteger {
    var publicKey: BigInteger

    do {
        publicKey = BigInteger(128, SecureRandom())
    } while (publicKey.gcd(phiValue) != BigInteger.ONE)
    return publicKey
}

private fun computeEulerFunction(firstPrime: BigInteger, secondPrime: BigInteger): BigInteger {
    val firstPrimeMinusOne = firstPrime.subtract(BigInteger.ONE)
    val secondPrimeMinusOne = secondPrime.subtract(BigInteger.ONE)

    return firstPrimeMinusOne.multiply(secondPrimeMinusOne)
}

private fun getSystemModulus(firstPrime: BigInteger, secondPrime: BigInteger): BigInteger =
    firstPrime.multiply(secondPrime)
