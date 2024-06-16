package org.example.utils

object HexUtils {

    fun hexStringToByteArray(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in hex.indices step 2) {
            val byte = hex.substring(i, i + 2).toInt(16).toByte()
            result[i / 2] = byte
        }
        return result
    }
}