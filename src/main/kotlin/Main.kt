package org.example

import org.example.aes.encryptWithPublicKey
import org.example.aes.generateAESKey
import org.example.aes.signEncryptedKey
import org.example.rsa.PublicKey
import org.example.rsa.generateKeyPair
import java.nio.file.Files
import java.nio.file.Paths

fun readProfessorPublicKey(filePath: String): Pair<String, String> {
    val path = Paths.get(filePath)
    val lines = Files.readAllLines(path)
    require(lines.size >= 2) { "The file must contain at least two lines." }
    return Pair(lines[0].trim(), lines[1].trim())
}

fun main() {

    val professorKey = readProfessorPublicKey("src/main/resources/professor_public_key.txt")

    val professorPublicKey = PublicKey.fromHex(
        exponent = professorKey.first,
        modulus = professorKey.second
    )
    val keyPair = generateKeyPair()
    val publicKey = keyPair.first
    val privateKey = keyPair.second

    println("Public key: ${publicKey.hexExponent()}")
    println("Private key: ${privateKey.hexExponent()}")

    val key = generateAESKey()

    val encryptedKey = encryptWithPublicKey(key, professorPublicKey)
    val signedKey = signEncryptedKey(encryptedKey, privateKey)

    println("Encrypted key(x): $encryptedKey")
    println("Signed key(sig x): $signedKey")
    println("Public key(pk a): $publicKey")
}