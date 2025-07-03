package org.example;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class ChatService {

    private final UserRepository userRepository;
    private final MessageRepository messageRepository;

    public ChatService(UserRepository userRepository,
                       MessageRepository messageRepository) {
        this.userRepository = userRepository;
        this.messageRepository = messageRepository;
    }

    /**
     * Registers a new user.
     */
    public User registerUser(String username, String publicKey) {
        User user = new User();
        user.setUsername(username);
        user.setPublicKey(publicKey);
        user.setCreatedAt(LocalDateTime.now());
        // delivered flag and messages table empty at start
        return userRepository.save(user);
    }


    public Message sendMessage(String senderUsername, String recipientUsername, String type,
                               String ciphertext, String iv) {
        Message message = new Message();
        message.setSenderUsername(senderUsername);
        message.setRecipientUsername(recipientUsername);
        message.setMessageType(type);
        message.setCiphertext(ciphertext);
        message.setIv(iv);
        message.setTimestamp(LocalDateTime.now());
        message.setDelivered(false);
        return messageRepository.save(message);
    }



    /**
     * Fetches all undelivered messages for the given receiver,
     * marks them delivered, and returns them.
     */


    @Transactional
    public List<Message> getUndeliveredMessages(String recipientUsername) {
        List<Message> messages = messageRepository.findByRecipientUsernameAndDeliveredFalse(recipientUsername);
        for (Message msg : messages) {
            msg.setDelivered(true);
        }
        messageRepository.saveAll(messages);
        return messages;
    }

    /**
     * Helper to look up a user by UUID.
     */
    public User getUserById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }
}
