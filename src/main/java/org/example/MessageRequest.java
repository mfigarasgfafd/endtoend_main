package org.example;

public record MessageRequest(
        String sender,
        String recipient,
        String type,       // np. "TEXT" lub "CTRL"
        String ciphertext,
        String iv
) {}