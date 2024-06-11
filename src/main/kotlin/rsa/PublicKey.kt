package org.example.rsa

import java.math.BigInteger

data class PublicKey(val exponent: BigInteger, val modulus: BigInteger) : Key {

    override fun hexExponent(): String {
        return exponent.toString(16)
    }

    override fun hexModulus(): String {
        return modulus.toString(16)
    }

    override fun toString(): String {
        return "(e=${hexExponent()}, N=${hexModulus()})"
    }

    companion object {
        fun fromHex(exponent: String, modulus: String): PublicKey {
            return PublicKey(BigInteger(exponent, 16), BigInteger(modulus, 16))
        }
    }
}
