package org.example;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Base64;
import java.util.List;
import java.util.UUID;


@RestController
@RequestMapping("/api")
public class ChatController {
    private final ChatService chatService;
    private final UserRepository userRepository;

    public ChatController(ChatService chatService, UserRepository userRepository) {
        this.chatService = chatService;
        this.userRepository = userRepository;
    }

    private User verifyUser(String authHeader) {
        // Basic Auth implementation
        String base64Credentials = authHeader.substring("Basic ".length());
        String credentials = new String(Base64.getDecoder().decode(base64Credentials));
        String[] values = credentials.split(":", 2);

        return userRepository.findByUsername(values[0])
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<User> getUserById(@PathVariable UUID userId) {
        return ResponseEntity.ok(chatService.getUserById(userId));
    }







    @PostMapping("/register")
    public ResponseEntity<User> registerUser(
            @RequestBody UserRegistrationRequest request
    ) {
        User user = chatService.registerUser(request.username(), request.publicKey());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/messages")
    public ResponseEntity<Message> sendMessage(
            @RequestBody MessageRequest request,
            @RequestHeader("Authorization") String authHeader
    ) {
        // Implement auth verification
        User sender = verifyUser(authHeader);
        User receiver = chatService.getUserById(request.receiverId());

        Message message = chatService.sendMessage(
                sender,
                receiver,
                request.ciphertext(),
                request.iv()
        );

        return ResponseEntity.ok(message);
    }

    @GetMapping("/messages")
    public ResponseEntity<List<Message>> getMessages(
            @RequestHeader("Authorization") String authHeader
    ) {
        User user = verifyUser(authHeader);
        return ResponseEntity.ok(chatService.getUndeliveredMessages(user));
    }
}