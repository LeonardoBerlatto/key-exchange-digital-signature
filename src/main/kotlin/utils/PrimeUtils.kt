package org.example.utils

import java.math.BigInteger
import java.security.SecureRandom

object PrimeUtils {

    fun generatePrime(size: Int): BigInteger = BigInteger.probablePrime(size, SecureRandom())
}