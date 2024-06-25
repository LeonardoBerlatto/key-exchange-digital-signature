package org.example.sha256

import org.example.rsa.PublicKey
import org.example.utils.HexUtils.byteArrayToHexString
import org.example.utils.HexUtils.hexStringToByteArray
import java.math.BigInteger
import java.security.MessageDigest

private const val SHA_256_KEY = "SHA-256"

fun hash(message: String): String {
    val bytes = MessageDigest.getInstance(SHA_256_KEY).digest(hexStringToByteArray(message))
    return byteArrayToHexString(bytes)
}

fun verifySignature(signature: String, hash: String, publicKey: PublicKey): Boolean {
    val numSignature = BigInteger(signature, 16)
    val numHash = BigInteger(hash, 16)

    val decryptedSignature = numSignature.modPow(publicKey.exponent, publicKey.modulus)
    return numHash == decryptedSignature
}