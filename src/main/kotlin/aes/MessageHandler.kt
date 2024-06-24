package org.example.aes

import org.example.rsa.PrivateKey
import org.example.rsa.PublicKey
import org.example.utils.HexUtils.hexStringToByteArray
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY = "AES"
private const val EXPECTED_KEY_SIZE = 128
private const val DEFAULT_IV_SIZE = 16


fun generateAESKey(): AESKey {
    val keyGen = KeyGenerator.getInstance(AES_KEY)
    keyGen.init(EXPECTED_KEY_SIZE)
    return AESKey(BigInteger(1, keyGen.generateKey().encoded))
}

fun encryptWithPublicKey(key: AESKey, publicKey: PublicKey): AESKey =
    AESKey(key.value.modPow(publicKey.exponent, publicKey.modulus))


fun signEncryptedKey(encryptedKey: AESKey, privateKey: PrivateKey): AESKey =
    AESKey(encryptedKey.value.modPow(privateKey.exponent, privateKey.modulus))



fun convertEncryptedMessage(hexMessage: String): AESData {
    val encryptedMessage = hexStringToByteArray(hexMessage)

    require(encryptedMessage.size >= DEFAULT_IV_SIZE) { "Encrypted message is too short to contain IV." }

    val iv = Arrays.copyOfRange(encryptedMessage, 0, DEFAULT_IV_SIZE)
    val encryptedData = Arrays.copyOfRange(encryptedMessage, DEFAULT_IV_SIZE, encryptedMessage.size)

    return AESData(iv, encryptedData)
}

fun convertSignature(signatureHex: String) = BigInteger(signatureHex, DEFAULT_IV_SIZE)

fun decryptAES(data: AESData, key: String): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val secretKey = SecretKeySpec(hexStringToByteArray(key), AES_KEY)
    val ivSpec = IvParameterSpec(data.iv)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
    val decryptedMessage = cipher.doFinal(data.encryptedMessage)
    return String(decryptedMessage, StandardCharsets.UTF_8)
}

fun encryptAES(message: ByteArray, key: ByteArray, iv: ByteArray): AESData {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val secretKey = SecretKeySpec(key, AES_KEY)
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    return AESData(
        iv = iv,
        encryptedMessage = cipher.doFinal(message)
    )
}


fun generateRandomIV(size: Int = DEFAULT_IV_SIZE): ByteArray {
    val iv = ByteArray(size)
    val secureRandom = SecureRandom()
    secureRandom.nextBytes(iv)
    return iv
}