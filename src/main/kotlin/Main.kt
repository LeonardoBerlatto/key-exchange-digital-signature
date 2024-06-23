package org.example

import org.example.aes.*
import org.example.rsa.Key
import org.example.rsa.PublicKey
import org.example.rsa.generateKeyPair
import org.example.sha256.hash
import org.example.sha256.verifySignature
import org.example.utils.HexUtils.hexStringToByteArray
import org.example.utils.StorageUtils.readAESKey
import org.example.utils.StorageUtils.readEncryptedMessage
import org.example.utils.StorageUtils.readProfessorPublicKey
import org.example.utils.StorageUtils.readSignature
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption.APPEND



fun writeToFile(key: Key) {
    val path = Paths.get("src/main/resources/${if (key.isPrivateKey()) "private" else "public"}_key.txt")
    Files.write(path, key.hexExponent().toByteArray())
    Files.write(path, "\n".toByteArray(), APPEND)
    Files.write(path, key.hexModulus().toByteArray(), APPEND)
}


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
    TODO("Not yet implemented")
}


fun main() {
    var mustExecute = true
    while (mustExecute) {
        println("0. Generate keys")
        println("1. Verify signature")
        println("2. Decrypt message")
        println("3. Invert and sign")
        println("4. Exit")
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
    }

}
