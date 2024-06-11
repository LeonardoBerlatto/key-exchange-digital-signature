package org.example.aes

import org.example.rsa.PrivateKey
import org.example.rsa.PublicKey
import java.math.BigInteger
import javax.crypto.KeyGenerator

private const val AES_KEY = "AES"
private const val EXPECTED_KEY_SIZE = 128

fun generateAESKey(): BigInteger {
    val keyGen = KeyGenerator.getInstance(AES_KEY)
    keyGen.init(EXPECTED_KEY_SIZE)
    return BigInteger(1, keyGen.generateKey().encoded)
}

fun encryptWithPublicKey(key: BigInteger, publicKey: PublicKey): BigInteger {
    return key.modPow(publicKey.exponent, publicKey.modulus)
}

fun signEncryptedKey(encryptedKey: BigInteger, privateKey: PrivateKey): BigInteger {
    return encryptedKey.modPow(privateKey.exponent, privateKey.modulus)
}