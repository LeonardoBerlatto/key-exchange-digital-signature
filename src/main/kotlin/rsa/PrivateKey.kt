package org.example.rsa

import java.math.BigInteger

data class PrivateKey(val exponent: BigInteger, val modulus: BigInteger) : Key {
    override fun hexExponent(): String {
        return exponent.toString(16)
    }

    override fun hexModulus(): String {
        return modulus.toString(16)
    }

    override fun toString(): String {
        return "PrivateKey(exponent=$exponent, modulus=$modulus)"
    }

    override fun isPrivateKey() = true

    companion object {
        fun fromHex(exponent: String, modulus: String): PrivateKey {
            return PrivateKey(
                exponent = BigInteger(exponent, 16),
                modulus = BigInteger(modulus, 16)
            )
        }
    }
}
