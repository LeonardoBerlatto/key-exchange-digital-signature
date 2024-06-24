package org.example.aes

import java.math.BigInteger

data class AESKey(val value: BigInteger) {

    fun toHex(): String {
        return value.toString(16)
    }

    override fun toString(): String {
        return toHex()
    }

    companion object {
        fun fromHex(hex: String): AESKey {
            return AESKey(BigInteger(hex, 16))
        }
    }


}
