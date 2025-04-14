package org.example;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface MessageRepository extends JpaRepository<Message, UUID> {
    List<Message> findByReceiverAndDeliveredFalse(User receiver);
    List<Message> findByReceiverAndReadFalse(User receiver);
}
