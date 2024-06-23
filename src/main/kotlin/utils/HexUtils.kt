package org.example.utils
import java.util.HexFormat

object HexUtils {

    fun hexStringToByteArray(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in hex.indices step 2) {
            val byte = hex.substring(i, i + 2).toInt(16).toByte()
            result[i / 2] = byte
        }
        return result
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun byteArrayToHexString(byteArray: ByteArray): String {
        return HexFormat.of().formatHex(byteArray)
    }
}