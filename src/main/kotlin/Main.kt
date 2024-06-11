package org.example

import org.example.rsa.KeyGeneratorService
import org.example.rsa.PublicKey
import java.nio.file.Files
import java.nio.file.Paths

fun readProfessorPublicKey(filePath: String): String {
    val path = Paths.get(filePath)
    return Files.readString(path).trim()
}

fun main() {

    val professorKey = PublicKey.fromHex(
        e = "2E76A0094D4CEE0AC516CA162973C895",
        n = readProfessorPublicKey("src/main/resources/professor_public_key.txt")
    )
    val keyPair = KeyGeneratorService.generateKeyPair()
    println("Public key: ${keyPair.first.hexExponent()}")
    println("Private key: ${keyPair.second.hexExponent()}")


}