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
        return "PublicKey(exponent=$exponent, modulus=$modulus)"
    }

    companion object {
        fun fromHex(e: String, n: String): PublicKey {
            return PublicKey(BigInteger(e, 16), BigInteger(n, 16))
        }
    }
}
