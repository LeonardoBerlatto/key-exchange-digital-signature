package org.example.aes

import org.example.rsa.PrivateKey
import org.example.rsa.PublicKey
import java.math.BigInteger
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

fun generateAESKey(): SecretKey {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128)
    return keyGen.generateKey()
}

fun encryptWithPublicKey(publicKey: PublicKey, key: SecretKey): BigInteger {
    val keyBytes = key.encoded
    val keyInt = BigInteger(1, keyBytes)
    return keyInt.modPow(publicKey.exponent, publicKey.modulus)
}

fun signEncryptedKey(privateKey: PrivateKey, encryptedKey: BigInteger): BigInteger {
    return encryptedKey.modPow(privateKey.exponent, privateKey.modulus)
}