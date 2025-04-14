package org.example;

import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class ChatService {
    private final UserRepository userRepository;
    private final MessageRepository messageRepository;

    public ChatService(UserRepository userRepository, MessageRepository messageRepository) {
        this.userRepository = userRepository;
        this.messageRepository = messageRepository;
    }

    public User registerUser(String username, String publicKey) {
        User user = new User();
        user.setUsername(username);
        user.setPublicKey(publicKey);
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    public Message sendMessage(User sender, User receiver, String ciphertext, String iv) {
        Message message = new Message();
        message.setSender(sender);
        message.setReceiver(receiver);
        message.setCiphertext(ciphertext);
        message.setIv(iv);
        message.setTimestamp(LocalDateTime.now());
        return messageRepository.save(message);
    }

    public List<Message> getUndeliveredMessages(User receiver) {
        List<Message> messages = messageRepository.findByReceiverAndDeliveredFalse(receiver);
        messages.forEach(msg -> msg.setDelivered(true));
        messageRepository.saveAll(messages);
        return messages;
    }
    public User getUserById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

}