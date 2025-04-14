package org.example;

public record UserRegistrationRequest(
        String username,
        String publicKey
) {}
