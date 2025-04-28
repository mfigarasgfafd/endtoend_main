package org.example;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;



public class Main {
    public static void main(String[] args) {

        ChatClient client = new ChatClient();
        client.initialize("alice", "ECDH"); // or "DH"
        client.sendMessage("bob", "Secret message");

    }
}


class DiffieHellmanExample {
    private byte[] sharedSecret;

    public void performKeyExchange() {
        try {
            BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
                    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
                    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
            BigInteger g = BigInteger.valueOf(2);

            // Use the same parameters for both parties
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);

            // Generate Alice's key pair
            KeyPairGenerator aliceKpg = KeyPairGenerator.getInstance("DiffieHellman");
            aliceKpg.initialize(dhSpec);
            KeyPair aliceKp = aliceKpg.generateKeyPair();

            // Generate Bob's key pair
            KeyPairGenerator bobKpg = KeyPairGenerator.getInstance("DiffieHellman");
            bobKpg.initialize(dhSpec);
            KeyPair bobKp = bobKpg.generateKeyPair();

            // Alice's agreement
            KeyAgreement aliceAgree = KeyAgreement.getInstance("DiffieHellman");
            aliceAgree.init(aliceKp.getPrivate());
            aliceAgree.doPhase(bobKp.getPublic(), true);

            // Bob's agreement
            KeyAgreement bobAgree = KeyAgreement.getInstance("DiffieHellman");
            bobAgree.init(bobKp.getPrivate());
            bobAgree.doPhase(aliceKp.getPublic(), true);

            // Generate and verify secrets
            byte[] aliceSecret = aliceAgree.generateSecret();
            byte[] bobSecret = bobAgree.generateSecret();

            if (!MessageDigest.isEqual(aliceSecret, bobSecret)) {
                throw new RuntimeException("DH secrets don't match");
            }

            // Store the verified secret
            this.sharedSecret = aliceSecret;

        } catch (Exception e) {
            throw new RuntimeException("DH exchange failed", e);
        }
    }

    public byte[] getSharedSecret() {
        if (sharedSecret == null) {
            throw new IllegalStateException("Perform key exchange first");
        }
        return sharedSecret;
    }
}

class ECDiffieHellmanExample {
    private byte[] sharedSecret;

    public void performKeyExchange() {
        try {
            KeyPairGenerator aliceKeyPairGen = KeyPairGenerator.getInstance("EC");
            aliceKeyPairGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair aliceKeyPair = aliceKeyPairGen.generateKeyPair();

            KeyPairGenerator bobKeyPairGen = KeyPairGenerator.getInstance("EC");
            bobKeyPairGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair bobKeyPair = bobKeyPairGen.generateKeyPair();

            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("ECDH");
            aliceKeyAgree.init(aliceKeyPair.getPrivate());

            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("ECDH");
            bobKeyAgree.init(bobKeyPair.getPrivate());

            // Complete both phases
            aliceKeyAgree.doPhase(bobKeyPair.getPublic(), true);
            bobKeyAgree.doPhase(aliceKeyPair.getPublic(), true);

            this.sharedSecret = aliceKeyAgree.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("ECDH failed", e);
        }
    }
    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}

class ManualDiffieHellman {
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
    private static final BigInteger G = BigInteger.valueOf(2);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private final SecureRandom secureRandom;
    private byte[] sharedSecret;

    public ManualDiffieHellman() {
        this.secureRandom = new SecureRandom();
    }

    // Changed to public
    public BigInteger generatePrivateKey() {
        BigInteger pMinusTwo = P.subtract(TWO);
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(P.bitLength(), secureRandom);
        } while (privateKey.compareTo(TWO) < 0 || privateKey.compareTo(pMinusTwo) > 0);
        return privateKey;
    }

    public BigInteger generatePublicKey(BigInteger privateKey) {
        return G.modPow(privateKey, P);
    }

    public byte[] computeSharedSecret(BigInteger privateKey, BigInteger otherPublicKey)
            throws InvalidKeyException {
        if (!isValidPublicKey(otherPublicKey)) {
            throw new InvalidKeyException("Invalid public key");
        }

        BigInteger sharedSecret = otherPublicKey.modPow(privateKey, P);

        if (!isValidSharedSecret(sharedSecret)) {
            throw new InvalidKeyException("Invalid shared secret computed");
        }

        return deriveKey(sharedSecret.toByteArray());
    }

    private boolean isValidPublicKey(BigInteger publicKey) {
        return publicKey.compareTo(TWO) >= 0 &&
                publicKey.compareTo(P.subtract(TWO)) <= 0;
    }

    private boolean isValidSharedSecret(BigInteger secret) {
        return !secret.equals(BigInteger.ONE) &&
                !secret.equals(BigInteger.ZERO) &&
                !secret.equals(P.subtract(BigInteger.ONE));
    }

    private byte[] deriveKey(byte[] sharedSecret) {
        try {
            // Example HKDF /w SHA-256
            HKDFParameters params = new HKDFParameters(sharedSecret, null, null);
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(params);

            byte[] derivedKey = new byte[32]; // 256 bits
            hkdf.generateBytes(derivedKey, 0, derivedKey.length);
            return derivedKey;
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }

    public byte[] getSharedSecret() {
        return new byte[0];
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }
}

class ManualECDiffieHellman {
    // using curve P-256 parameters (secp256r1)
    private static final BigInteger P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    private static final BigInteger B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final ECPoint G = new ECPoint(
            new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
            new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
    );

    private final SecureRandom secureRandom;

    public ManualECDiffieHellman() {
        this.secureRandom = new SecureRandom();
    }

    // Add state fields
    private BigInteger privateKey;
    private ECPoint publicKey;
    private byte[] sharedSecret;

    public void generateKeyPair() throws InvalidKeyException {
        this.privateKey = generatePrivateKey();
        this.publicKey = generatePublicKey(privateKey);
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public void computeSharedSecret(ECPoint otherPublicKey) throws InvalidKeyException {
        if (!isPointOnCurve(otherPublicKey)) {
            throw new InvalidKeyException("Public key point is not on the curve");
        }

        ECPoint sharedPoint = multiplyPoint(otherPublicKey, privateKey);
        if (sharedPoint.infinity) {
            throw new InvalidKeyException("Invalid shared point at infinity");
        }

        assert sharedPoint.x != null;
        this.sharedSecret = deriveKey(sharedPoint.x.toByteArray());
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }


    static class ECPoint {
        final BigInteger x;
        final BigInteger y;
        final boolean infinity;

        ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
            this.infinity = false;
        }

        private ECPoint(boolean infinity) {
            this.x = null;
            this.y = null;
            this.infinity = infinity;
        }

        static ECPoint INFINITY = new ECPoint(true);
    }

    public BigInteger generatePrivateKey() {
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(N.bitLength(), secureRandom);
        } while (privateKey.compareTo(BigInteger.ONE) < 0 || privateKey.compareTo(N) >= 0);
        return privateKey;
    }

    public ECPoint generatePublicKey(BigInteger privateKey) throws InvalidKeyException {
        if (privateKey.compareTo(BigInteger.ONE) < 0 || privateKey.compareTo(N) >= 0) {
            throw new InvalidKeyException("Invalid private key");
        }
        return multiplyPoint(G, privateKey);
    }

    public byte[] computeSharedSecret(BigInteger privateKey, ECPoint otherPublicKey)
            throws InvalidKeyException {
        if (!isPointOnCurve(otherPublicKey)) {
            throw new InvalidKeyException("Public key point is not on the curve");
        }

        ECPoint sharedPoint = multiplyPoint(otherPublicKey, privateKey);
        if (sharedPoint.infinity) {
            throw new InvalidKeyException("Invalid shared point at infinity");
        }

        assert sharedPoint.x != null;
        return deriveKey(sharedPoint.x.toByteArray());
    }

    private ECPoint addPoints(ECPoint p1, ECPoint p2) {
        if (p1.infinity) return p2;
        if (p2.infinity) return p1;

        BigInteger slope;
        if (p1.x.equals(p2.x)) {
            if (p1.y.equals(p2.y)) {
                // Point doubling
                if (p1.y.equals(BigInteger.ZERO)) return ECPoint.INFINITY;
                BigInteger numerator = p1.x.pow(2).multiply(BigInteger.valueOf(3)).add(A);
                BigInteger denominator = p1.y.multiply(BigInteger.valueOf(2));
                slope = numerator.multiply(denominator.modInverse(P)).mod(P);
            } else {
                return ECPoint.INFINITY;
            }
        } else {
            // Point addition
            assert p2.y != null;
            BigInteger numerator = p2.y.subtract(p1.y);
            assert p2.x != null;
            BigInteger denominator = p2.x.subtract(p1.x);
            slope = numerator.multiply(denominator.modInverse(P)).mod(P);
        }

        BigInteger x3 = slope.pow(2).subtract(p1.x).subtract(p2.x).mod(P);
        BigInteger y3 = slope.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(P);

        return new ECPoint(x3, y3);
    }

    private ECPoint multiplyPoint(ECPoint point, BigInteger scalar) {
        ECPoint result = ECPoint.INFINITY;
        ECPoint temp = point;

        for (int i = 0; i < scalar.bitLength(); i++) {
            if (scalar.testBit(i)) {
                result = addPoints(result, temp);
            }
            temp = addPoints(temp, temp);
        }

        return result;
    }

    private boolean isPointOnCurve(ECPoint point) {
        if (point.infinity) return false;
        if (point.x == null || point.y == null) return false;

        try {
            // Verify using modular arithmetic
            BigInteger ySquared = point.y.modPow(TWO, P);
            BigInteger xCubed = point.x.modPow(THREE, P);
            BigInteger aX = A.multiply(point.x).mod(P);
            BigInteger right = xCubed.add(aX).add(B).mod(P);

            return ySquared.equals(right);
        } catch (NullPointerException e) {
            return false;
        }
    }
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    private byte[] deriveKey(byte[] sharedSecret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(sharedSecret);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}