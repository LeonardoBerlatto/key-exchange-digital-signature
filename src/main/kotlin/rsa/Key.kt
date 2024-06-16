package org.example.rsa

interface Key {
    fun hexExponent(): String
    fun hexModulus(): String
    fun isPrivateKey(): Boolean
}