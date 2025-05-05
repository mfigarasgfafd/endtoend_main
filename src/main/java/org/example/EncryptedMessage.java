package org.example;


import java.nio.ByteBuffer;
import java.util.Base64;

public record EncryptedMessage(String ciphertext, String iv) {
    public static EncryptedMessage fromBytes(byte[] encryptedData) {
        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[12];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);
        return new EncryptedMessage(
                Base64.getEncoder().encodeToString(ciphertext),
                Base64.getEncoder().encodeToString(iv)
        );
    }

    public byte[] toByteArray() {
        ByteBuffer buffer = ByteBuffer.allocate(12 + Base64.getDecoder().decode(ciphertext).length);
        buffer.put(Base64.getDecoder().decode(iv));
        buffer.put(Base64.getDecoder().decode(ciphertext));
        return buffer.array();
    }
}