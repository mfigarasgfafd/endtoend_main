package org.example;

import jakarta.persistence.Entity;
import jakarta.persistence.*;


import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "messages")
public class Message {
    @Id @GeneratedValue
    private UUID id;

    // Store only the usernames
    @Column(nullable = false)
    private String senderUsername;

    @Column(nullable = false)
    private String recipientUsername;
    // nowa kolumna: typ wiadomości
    @Column(nullable = false)
    private String messageType; // np. "TEXT" lub "CTRL"

    @Column(length = 4096, nullable = false)
    private String ciphertext;

    @Column(length = 256, nullable = false)
    private String iv;

    @Column(nullable = false)
    private boolean delivered = false;

    @Column(nullable = false)
    private LocalDateTime timestamp = LocalDateTime.now();

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getMessageType() { return messageType; }
    public void setMessageType(String messageType) { this.messageType = messageType; }


    public String getSenderUsername() {
        return senderUsername;
    }

    public void setSenderUsername(String senderUsername) {
        this.senderUsername = senderUsername;
    }

    public String getRecipientUsername() {
        return recipientUsername;
    }

    public void setRecipientUsername(String recipientUsername) {
        this.recipientUsername = recipientUsername;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public boolean isDelivered() {
        return delivered;
    }

    public void setDelivered(boolean delivered) {
        this.delivered = delivered;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}