package org.example;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue
    private UUID userId;

    @Column(nullable = false, unique = true)
    private String username;

    @Lob
    @Column(nullable = false)
    private String publicKey;

    @Transient // This field won't be persisted
    private String password;
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    private LocalDateTime createdAt;
//    private LocalDateTime lastSeen;

    public String getUserIdString() {
        return userId != null ? userId.toString() : "";
    }
    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

//    public LocalDateTime getLastSeen() {
//        return lastSeen;
//    }
//
//    public void setLastSeen(LocalDateTime lastSeen) {
//        this.lastSeen = lastSeen;
//    }
}
