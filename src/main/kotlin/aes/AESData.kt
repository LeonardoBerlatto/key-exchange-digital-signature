package org.example.aes

data class AESData(
    val iv: ByteArray,
    val encryptedMessage: ByteArray
)
