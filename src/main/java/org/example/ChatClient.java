package org.example;

import java.security.KeyPair;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import org.springframework.web.reactive.function.client.WebClient;

import java.security.PublicKey;


public class ChatClient {
    private User localUser;
    private KeyPair keyPair;
    private final WebClient webClient;
    private String baseUrl = "http://localhost:8080";
    private String keyExchangeAlgorithm = "DH";

    public ChatClient() {
        this.webClient = WebClient.builder()
                .baseUrl(baseUrl)
                .build();
    }

    public void initialize(String username, String algorithm) {
        this.keyExchangeAlgorithm = algorithm;
        this.keyPair = generateKeyPair(algorithm);

        String publicKey = Base64.getEncoder().encodeToString(
                keyPair.getPublic().getEncoded()
        );

        this.localUser = webClient.post()
                .uri("/api/register")
                .bodyValue(new UserRegistrationRequest(username, publicKey))
                .retrieve()
                .bodyToMono(User.class)
                .block();
    }

    public void sendMessage(String recipientUsername, String message) {
        try {
            // Get recipient's public key
            User recipient = webClient.get()
                    .uri("/api/users?username={username}", recipientUsername)
                    .retrieve()
                    .bodyToMono(User.class)
                    .block();

            if (recipient == null) {
                System.err.println("Recipient not found: " + recipientUsername);
                return;
            }

            // Perform key exchange
            byte[] sharedSecret = computeSharedSecret(
                    recipient.getPublicKey(),
                    this.keyExchangeAlgorithm
            );

            // Encrypt message
            CipherResult encrypted = encryptMessage(message, sharedSecret);

            // Send to backend - convert UUID to String
            webClient.post()
                    .uri("/api/messages")
                    .bodyValue(new MessageRequest(
                            this.localUser.getUserId().toString(),  // Convert UUID to String
                            recipient.getUserId().toString(),       // Convert UUID to String
                            encrypted.ciphertext(),
                            encrypted.iv()
                    ))
                    .retrieve()
                    .bodyToMono(Void.class)
                    .block();

        } catch (Exception e) {
            System.err.println("Message send failed: " + e.getMessage());
        }
    }
    private KeyPair generateKeyPair(String algorithm) {
        try {
            KeyPairGenerator kpg;
            switch (algorithm.toUpperCase()) {
                case "ECDH":
                    kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(new ECGenParameterSpec("secp256r1"));
                    break;
                case "DH":
                default:
                    kpg = KeyPairGenerator.getInstance("DH");
                    kpg.initialize(2048); // Use appropriate parameter spec
            }
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Key generation failed", e);
        }
    }



    private byte[] computeSharedSecret(String recipientPublicKey, String algorithm) {
        try {
            PublicKey publicKey = decodePublicKey(recipientPublicKey, algorithm);
            KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);
            keyAgreement.init(this.keyPair.getPrivate());
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("Key exchange failed", e);
        }
    }

    private PublicKey decodePublicKey(String encodedKey, String algorithm) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new RuntimeException("Invalid public key", e);
        }
    }

    // Add encryption/decryption methods
    private record CipherResult(String ciphertext, String iv) {}

    private CipherResult encryptMessage(String plaintext, byte[] sharedSecret) {
        // Implement your encryption logic
        // Return ciphertext + IV
        return null;
    }
}