package org.example.aes

import org.example.rsa.PrivateKey
import org.example.rsa.PublicKey
import java.math.BigInteger
import javax.crypto.KeyGenerator

fun generateAESKey(): BigInteger {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128)
    keyGen.generateKey()
    return BigInteger(1, keyGen.generateKey().encoded)
}

fun encryptWithPublicKey(key: BigInteger, publicKey: PublicKey): BigInteger {
    return key.modPow(publicKey.exponent, publicKey.modulus)
}

fun signEncryptedKey(encryptedKey: BigInteger, privateKey: PrivateKey): BigInteger {
    return encryptedKey.modPow(privateKey.exponent, privateKey.modulus)
}