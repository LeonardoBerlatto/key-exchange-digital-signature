package org.example.utils

import java.nio.file.Files
import java.nio.file.Paths

object StorageUtils {

    fun readEncryptedMessage() = Files.readAllLines(Paths.get("src/main/resources/c_sign.txt"))[0]

    fun readSignature() = Files.readAllLines(Paths.get("src/main/resources/c_sign.txt"))[1]

    fun readAESKey() = Files.readAllBytes(Paths.get("src/main/resources/aes_key.txt"))

    fun readProfessorPublicKey(): Pair<String, String> {
        val path = Paths.get("src/main/resources/professor_public_key.txt")
        val lines = Files.readAllLines(path)
        require(lines.size >= 2) { "The file must contain at least two lines." }
        return Pair(lines[0].trim(), lines[1].trim())
    }
}