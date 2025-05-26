package org.example;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;



// KLASA DO TESTOWANIA

@SpringBootApplication
public class SecureChatApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureChatApplication.class, args);
    }

    @Bean
    @Profile("!test") // Exclude from tests
    public CommandLineRunner demoData(
            UserRepository userRepository,
            ChatService chatService
    ) {
        return args -> {
//            // Generate test users with keys
//            User alice = createTestUser("alice", "ECDH");
//            User bob = createTestUser("bob", "DH");
//
//            userRepository.save(alice);
//            userRepository.save(bob);

            System.out.println("Test users created:");
//            System.out.println("Alice ID: " + alice.getUserId());
//            System.out.println("Bob ID: " + bob.getUserId());
        };
    }

//    private User createTestUser(String username, String algorithm) throws Exception {
//        KeyPair keyPair = generateKeyPair(algorithm);
//        String publicKey = Base64.getEncoder().encodeToString(
//                keyPair.getPublic().getEncoded()
//        );
//
//        User user = new User();
//        user.setUsername(username);
//        user.setPublicKey(publicKey);
//        return user;
//    }
//
    private KeyPair generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator kpg;
        switch (algorithm.toUpperCase()) {
            case "ECDH":
                kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                break;
            case "DH":
            default:
                kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(2048);
        }
        return kpg.generateKeyPair();
    }
}