package org.example;

import java.util.UUID;

public record MessageRequest(
        UUID receiverId,
        String ciphertext,
        String iv
) {}
