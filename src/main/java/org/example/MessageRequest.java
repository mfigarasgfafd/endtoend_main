package org.example;

public record MessageRequest(
        String sender,
        String recipient,
        String ciphertext,
        String iv
) {}