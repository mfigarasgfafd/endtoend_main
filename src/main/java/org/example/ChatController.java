package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.MediaType;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;


@RestController
@RequestMapping("/api")
public class ChatController {
    // No changes needed to controller structure
    private final ChatService chatService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;


    public ChatController(ChatService chatService, UserRepository userRepository, ObjectMapper objectMapper) {
        this.chatService = chatService;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
    }

    // Existing endpoints remain identical
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        User user = new User();
        user.setUsername(request.username());
        user.setPublicKey(request.publicKey() != null ? request.publicKey() : "");
        user.setCreatedAt(LocalDateTime.now());

        // Add empty password field to satisfy Spring Security
        user.setPassword("");

        userRepository.save(user);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/messages")
    public ResponseEntity<Void> receiveMessage(@RequestBody MessageRequest request,
                                               @RequestHeader("Authorization") String authHeader) {
        User user = verifyUser(authHeader);
        if (!user.getUsername().equals(request.sender())) {
            return ResponseEntity.status(403).build();
        }
        String type = request.type();
        if (!"TEXT".equals(type) && !"CTRL".equals(type)) {
            return ResponseEntity.badRequest().build();
        }
        chatService.sendMessage(request.sender(),
                request.recipient(),
                request.type(),
                request.ciphertext(),
                request.iv());
        return ResponseEntity.ok().build();
    }


    private String extractUsername(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        String base64 = authHeader.substring(6);
        String decoded = new String(Base64.getDecoder().decode(base64));
        return decoded.split(":", 2)[0];
    }

    @GetMapping("/messages/{username}")
    public ResponseEntity<List<Message>> getMessages(@PathVariable String username,
                                                     @RequestHeader("Authorization") String authHeader) {
        User user = verifyUser(authHeader);
        if (!user.getUsername().equals(username)) {
            return ResponseEntity.status(403).build();
        }
        List<Message> messages = chatService.getUndeliveredMessages(username);
        return ResponseEntity.ok(messages);
    }


    // Endpoint do usuwania public key
    @DeleteMapping("/users/{username}/public-key")
    public ResponseEntity<Void> deletePublicKey(@PathVariable String username,
                                                @RequestHeader("Authorization") String authHeader) {
        User user = verifyUser(authHeader);
        if (!user.getUsername().equals(username)) {
            return ResponseEntity.status(403).build();
        }
        user.setPublicKey("");
        userRepository.save(user);
        return ResponseEntity.ok().build();
    }




    @PutMapping(
            path = "/users/{username}/public-key",
            consumes = MediaType.TEXT_PLAIN_VALUE
    )
    public ResponseEntity<?> updatePublicKey(
            @PathVariable String username,
            @RequestBody String publicKey,
            @RequestHeader("Authorization") String authHeader
    ) {
        // 1) verify and fetch the authenticated user
        User user = verifyUser(authHeader);
        if (!user.getUsername().equals(username)) {
            // refuse if auth‐header user != path variable
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        // 2) store the new key
        user.setPublicKey(publicKey);

        // 3) persist it
        userRepository.save(user);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/users/{username}/public-key")
    public ResponseEntity<String> getPublicKey(@PathVariable("username") String username) { // Add explicit path variable
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return ResponseEntity.ok(user.getPublicKey());
    }


    @GetMapping("/users/exists/{username}")
    public ResponseEntity<Boolean> userExists(@PathVariable("username") String username) { // Explicit path variable name
        return ResponseEntity.ok(userRepository.existsByUsername(username));
    }



    private User verifyUser(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        String base64Credentials = authHeader.substring("Basic ".length());
        String credentials = new String(Base64.getDecoder().decode(base64Credentials));
        String username = credentials.split(":", 2)[0];

        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

}