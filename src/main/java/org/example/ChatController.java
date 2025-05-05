package org.example;

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

    public ChatController(ChatService chatService,
                          UserRepository userRepository) {
        this.chatService = chatService;
        this.userRepository = userRepository;
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
    public ResponseEntity<Void> receiveMessage(
            @RequestBody MessageRequest req,
            @RequestHeader("Authorization") String authHeader
    ) {
        // Verify Basic‐Auth user matches the sender field
        String authUsername = extractUsername(authHeader);
        if (!authUsername.equals(req.sender())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Sender mismatch");
        }

        // Ensure recipient exists
        if (!userRepository.existsByUsername(req.recipient())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Recipient not found");
        }

        // Persist
        chatService.sendMessage(
                req.sender(),
                req.recipient(),
                req.ciphertext(),
                req.iv()
        );
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
    public List<Message> getMessages(
            @PathVariable String username,
            @RequestHeader("Authorization") String authHeader
    ) {
        String authUsername = extractUsername(authHeader);
        if (!authUsername.equals(username)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your messages");
        }
        return chatService.getUndeliveredMessages(username);
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