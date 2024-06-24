package org.example.utils

import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption.APPEND

object StorageUtils {

    fun readEncryptedMessage() = Files.readAllLines(Paths.get("src/main/resources/c_sign.txt"))[0]

    fun readSignature() = Files.readAllLines(Paths.get("src/main/resources/c_sign.txt"))[1]

    fun readAESKey() = Files.readAllLines(Paths.get("src/main/resources/aes_key.txt"))[0]

    fun readDecryptedMessage() = Files.readAllLines(Paths.get("src/main/resources/decrypted_message.txt"))[0]

    fun readProfessorPublicKey(): Pair<String, String> {
        val path = Paths.get("src/main/resources/professor_public_key.txt")
        val lines = Files.readAllLines(path)
        require(lines.size >= 2) { "The file must contain at least two lines." }
        return Pair(lines[0].trim(), lines[1].trim())
    }

    fun readPrivateKey(): Pair<String, String> {
        val path = Paths.get("src/main/resources/private_key.txt")
        val lines = Files.readAllLines(path)
        require(lines.size >= 2) { "The file must contain at least two lines." }
        return Pair(lines[0].trim(), lines[1].trim())
    }

    fun writeMessageAndSignature(message: String, signature: String) {
        val path = Paths.get("src/main/resources/final_encrypted_message.txt")
        Files.write(path, message.toByteArray())
        Files.write(path, "\n".toByteArray(), APPEND)
        Files.write(path, signature.toByteArray(), APPEND)
    }
}