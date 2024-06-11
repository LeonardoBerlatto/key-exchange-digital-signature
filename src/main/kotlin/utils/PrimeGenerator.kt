package org.example.utils

import java.math.BigInteger
import java.security.SecureRandom

object PrimeGenerator {

    fun generatePrime(): BigInteger = BigInteger.probablePrime(1024, SecureRandom())
}