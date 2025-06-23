package org.example;

import org.openjdk.jmh.annotations.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.Base64;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class PerformanceTesting {
    // Shared state for DH
    private KeyPairGenerator dhKeyGen;

    // Shared state for ECDH
    private KeyPairGenerator ecdhKeyGen;

    // Manual DH instance
    private ManualDiffieHellman manualDh;
    private ManualDiffieHellman manualDhPeer;

    // Manual ECDH instance and pre-parsed partner point
    private ManualECDiffieHellman manualEcdh;
    private ManualECDiffieHellman manualEcdhPeer;
    private ManualECDiffieHellman.ECPointAffine manualEcdhPeerPoint;

    // Symmetric AES-GCM state
    private SecretKey aesKey;
    private byte[] samplePlaintext;
    private byte[] encryptedPayload;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Setup(Level.Trial)
    public void setup() throws Exception {
        // Library DH
        dhKeyGen = KeyPairGenerator.getInstance("DH");
        dhKeyGen.initialize(2048);

        // Library ECDH
        ecdhKeyGen = KeyPairGenerator.getInstance("EC");
        ecdhKeyGen.initialize(new ECGenParameterSpec("secp256r1"));

        // Manual DH pair
        manualDh = new ManualDiffieHellman();
        manualDh.initialize();
        manualDhPeer = new ManualDiffieHellman();
        manualDhPeer.initialize();

        // Manual ECDH pair
        manualEcdh = new ManualECDiffieHellman();
        manualEcdh.generateKeyPair();
        manualEcdhPeer = new ManualECDiffieHellman();
        manualEcdhPeer.generateKeyPair();

        // Pre-parse manualEcdhPeer's EC point once
        String pubHex = manualEcdhPeer.getPublicKey();
        byte[] pubBytes = hexStringToBytes(pubHex);
        byte[] xBytes = new byte[32];
        byte[] yBytes = new byte[32];
        System.arraycopy(pubBytes, 1, xBytes, 0, 32);
        System.arraycopy(pubBytes, 33, yBytes, 0, 32);
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);
        manualEcdhPeerPoint = new ManualECDiffieHellman.ECPointAffine(x, y);

        // AES-GCM setup
        // derive 256-bit key from zeroed secret for benchmarking
        byte[] keyBytes = new byte[32];
        aesKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        samplePlaintext = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
        encryptedPayload = encryptMessage(new String(samplePlaintext, StandardCharsets.UTF_8), aesKey);
    }

    @Benchmark
    public byte[] libraryDhExchange() throws Exception {
        KeyPair kp = dhKeyGen.generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(kp.getPrivate());
        ka.doPhase(kp.getPublic(), true);
        return ka.generateSecret();
    }

    @Benchmark
    public byte[] manualDhExchange() throws Exception {
        manualDh.computeSharedSecret(manualDhPeer.getPublicKey());
        return manualDh.getSharedSecret();
    }

    @Benchmark
    public byte[] libraryEcdhExchange() throws Exception {
        KeyPair kp = ecdhKeyGen.generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(kp.getPublic(), true);
        return ka.generateSecret();
    }

    @Benchmark
    public byte[] manualEcdhExchange() throws Exception {
        manualEcdh.computeSharedSecret(manualEcdhPeerPoint);
        return manualEcdh.getSharedSecret();
    }

    @Benchmark
    public byte[] encryptBaseline() throws Exception {
        return encryptMessage(new String(samplePlaintext, StandardCharsets.UTF_8), aesKey);
    }

    @Benchmark
    public String decryptBaseline() throws Exception {
        // split iv & ciphertext
        ByteBuffer buf = ByteBuffer.wrap(encryptedPayload);
        byte[] iv = new byte[12]; buf.get(iv);
        byte[] ct = new byte[buf.remaining()]; buf.get(ct);
        return decryptMessage(iv, ct, aesKey);
    }

    @Benchmark
    public void spamEncrypt100() throws Exception {
        for (int i = 0; i < 100; i++) {
            encryptMessage(new String(samplePlaintext, StandardCharsets.UTF_8), aesKey);
        }
    }

    @Benchmark
    public void spamDecrypt100() throws Exception {
        for (int i = 0; i < 100; i++) {
            ByteBuffer buf = ByteBuffer.wrap(encryptedPayload);
            byte[] iv = new byte[12]; buf.get(iv);
            byte[] ct = new byte[buf.remaining()]; buf.get(ct);
            decryptMessage(iv, ct, aesKey);
        }
    }

    // to samo co w maingui
    private static byte[] encryptMessage(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv).put(ciphertext);
        return buffer.array();
    }

    private static String decryptMessage(byte[] iv, byte[] ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] plain = cipher.doFinal(ciphertext);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static byte[] hexStringToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
