package org.example

import org.example.aes.*
import org.example.rsa.PrivateKey
import org.example.rsa.PublicKey
import org.example.rsa.generateKeyPair
import org.example.sha256.hash
import org.example.sha256.verifySignature
import org.example.utils.HexUtils.byteArrayToHexString
import org.example.utils.HexUtils.hexStringToByteArray
import org.example.utils.StorageUtils.readAESKey
import org.example.utils.StorageUtils.readDecryptedMessage
import org.example.utils.StorageUtils.readEncryptedMessage
import org.example.utils.StorageUtils.readPrivateKey
import org.example.utils.StorageUtils.readProfessorPublicKey
import org.example.utils.StorageUtils.readSignature
import org.example.utils.StorageUtils.writeMessageAndSignature
import org.example.utils.StorageUtils.writeToFile
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Paths


private const val LINE_BREAKER = "-----------------------------"

fun generateKeys() {
    val professorKey = readProfessorPublicKey()

    val professorPublicKey = PublicKey.fromHex(
        exponent = professorKey.first,
        modulus = professorKey.second
    )
    val keyPair = generateKeyPair()
    val publicKey = keyPair.first
    val privateKey = keyPair.second

    writeToFile(privateKey)
    writeToFile(publicKey)

    val key = generateAESKey()
    Files.write(Paths.get("src/main/resources/aes_key.txt"), key.toHex().toByteArray())

    val encryptedKey = encryptWithPublicKey(key, professorPublicKey)
    Files.write(Paths.get("src/main/resources/aes_encrypted_key.txt"), encryptedKey.toHex().toByteArray())

    val signedKey = signEncryptedKey(encryptedKey, privateKey)
    Files.write(Paths.get("src/main/resources/aes_signed_key.txt"), signedKey.toHex().toByteArray())

    println("Encrypted key(x): $encryptedKey")
    println("Signed key(sig x): $signedKey")
    println("Public key(pk a): $publicKey")
}

fun verifySignature() {
    val professorKey = readProfessorPublicKey()
    val professorPublicKey = PublicKey.fromHex(
        exponent = professorKey.first,
        modulus = professorKey.second
    )

    val message = readEncryptedMessage()
    val signature = readSignature()

    val hashedMessage = hash(message)
    val isVerified = verifySignature(signature, hashedMessage, professorPublicKey)
    println("Signature ${if (isVerified) "verified" else "not verified"}")
}

fun decryptMessage() {
    val message = readEncryptedMessage()
    val data = convertEncryptedMessage(message)

   try {
       val decryptedMessage = decryptAES(data, readAESKey())
       println("Successfully decrypted message: $decryptedMessage")
   } catch (e: Exception) {
       println("Failed to decrypt message")
   }
}


fun invertAndSign() {
    val decryptedMessage = readDecryptedMessage().reversed()

    val aesData = encryptAES(
        message = decryptedMessage.toByteArray(),
        key = hexStringToByteArray(readAESKey()),
        iv = generateRandomIV()
    )
    val fullMessage = byteArrayToHexString(aesData.iv) + byteArrayToHexString(aesData.encryptedMessage)


    val hashedMessage = hash(fullMessage)

    val privateKeyExponentAndModulus = readPrivateKey()
    val privateKey = PrivateKey.fromHex(
        exponent = privateKeyExponentAndModulus.first,
        modulus = privateKeyExponentAndModulus.second
    )

    val signature = BigInteger(hashedMessage, 16).modPow(privateKey.exponent, privateKey.modulus).toString(16)
    writeMessageAndSignature(fullMessage, signature)

    println("Encrypted message(c_inv): $fullMessage")
    println("Signature(sigh_inv): $signature")
}



fun main() {
    var mustExecute = true
    while (mustExecute) {
        println("------------Part 1-----------")
        println("0. Generate keys")
        println("------------Part 2-----------")
        println("1. Verify signature")
        println("2. Decrypt message")
        println("3. Invert and sign")
        println("4. Exit")
        println(LINE_BREAKER)
        print("Enter your choice: ")
        val choice = readLine()!!.toInt()
        when (choice) {
            0 -> generateKeys()
            1 -> verifySignature()
            2 -> decryptMessage()
            3 -> invertAndSign()
            4 -> mustExecute = false
            else -> println("Invalid choice")
        }
        println(LINE_BREAKER)
    }

}
