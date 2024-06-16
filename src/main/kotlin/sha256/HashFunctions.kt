package org.example.sha256

import org.example.rsa.PublicKey
import java.math.BigInteger
import java.security.MessageDigest

private const val SHA_256_KEY = "SHA-256"

fun hash(message: ByteArray): ByteArray {
    return MessageDigest.getInstance(SHA_256_KEY).digest(message)
}

fun verifySignature(signature: String, hash: ByteArray, publicKey: PublicKey): Boolean {
    val numSignature = BigInteger(signature, 16)
    val numHash = BigInteger(1, hash)

    val decryptedSignature = numSignature.modPow(publicKey.exponent, publicKey.modulus)
    return numHash == decryptedSignature
}