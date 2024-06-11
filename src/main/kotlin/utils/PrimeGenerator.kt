package org.example.utils

import java.math.BigInteger
import java.security.SecureRandom

object PrimeGenerator {

    fun generatePrime(size: Int): BigInteger = BigInteger.probablePrime(size, SecureRandom())
}