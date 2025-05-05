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

    /**
     * Persists an encrypted message from sender -> receiver.
     */
    public Message sendMessage(
            String senderUsername,
            String recipientUsername,
            String ciphertext,
            String iv
    ) {
        Message msg = new Message();
        msg.setSenderUsername(senderUsername);
        msg.setRecipientUsername(recipientUsername);
        msg.setCiphertext(ciphertext);
        msg.setIv(iv);
        msg.setTimestamp(LocalDateTime.now());
        msg.setDelivered(false);
        return messageRepository.save(msg);
    }

    /**
     * Fetches all undelivered messages for the given receiver,
     * marks them delivered, and returns them.
     */
    @Transactional
    public List<Message> getUndeliveredMessages(String recipientUsername) {
        List<Message> msgs = messageRepository
                .findByRecipientUsernameAndDeliveredFalse(recipientUsername);

        if (!msgs.isEmpty()) {
            msgs.forEach(m -> m.setDelivered(true));
            messageRepository.saveAll(msgs);
        }
        return msgs;
    }

    /**
     * Helper to look up a user by UUID.
     */
    public User getUserById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }
}
