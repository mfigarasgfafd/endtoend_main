package org.example;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;


public interface MessageRepository extends JpaRepository<Message, UUID> {
    List<Message> findByRecipientUsernameAndDeliveredFalse(String recipientUsername);
}
//public interface MessageRepository extends JpaRepository<Message, UUID> {
//    // Always work with String usernames here
//    List<Message> findByRecipientUsernameAndDeliveredFalse(String recipientUsername);
//}