package org.example;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

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

        System.out.println("--- Diffie-Hellman Key Exchange ---");
        DiffieHellmanExample dhExample = new DiffieHellmanExample();
        dhExample.performKeyExchange();

        System.out.println("\n--- Elliptic Curve Diffie-Hellman Key Exchange ---");
        ECDiffieHellmanExample ecDhExample = new ECDiffieHellmanExample();
        ecDhExample.performKeyExchange();



        System.out.println("\n--- Manual Elliptic Curve Diffie-Hellman Key Exchange ---");
        try {
            ManualECDiffieHellman alice = new ManualECDiffieHellman();
            ManualECDiffieHellman bob = new ManualECDiffieHellman();

            // Generate private keys
            BigInteger alicePrivate = alice.generatePrivateKey();
            BigInteger bobPrivate = bob.generatePrivateKey();

            // Generate public keys
            ManualECDiffieHellman.ECPoint alicePublic = alice.generatePublicKey(alicePrivate);
            ManualECDiffieHellman.ECPoint bobPublic = bob.generatePublicKey(bobPrivate);

            // Compute shared secrets
            byte[] aliceShared = alice.computeSharedSecret(alicePrivate, bobPublic);
            byte[] bobShared = bob.computeSharedSecret(bobPrivate, alicePublic);

            // Verify
            if (Arrays.equals(aliceShared, bobShared)) {
                System.out.println("Key exchange successful!");
            } else {
                System.out.println("Key exchange failed!");
            }

        } catch (InvalidKeyException e) {
            System.err.println("Key exchange failed: " + e.getMessage());
        }


        System.out.println("\n--- Manual Diffie-Hellman Key Exchange ---");

        try {
            // Create instances for Alice and Bob
            ManualDiffieHellman alice = new ManualDiffieHellman();
            ManualDiffieHellman bob = new ManualDiffieHellman();

            // Generate private keys
            BigInteger alicePrivate = alice.generatePrivateKey();
            BigInteger bobPrivate = bob.generatePrivateKey();

            // Generate public keys
            BigInteger alicePublic = alice.generatePublicKey(alicePrivate);
            BigInteger bobPublic = bob.generatePublicKey(bobPrivate);

            // Compute shared secrets
            byte[] aliceShared = alice.computeSharedSecret(alicePrivate, bobPublic);
            byte[] bobShared = bob.computeSharedSecret(bobPrivate, alicePublic);


            // demonstration:
            if (Arrays.equals(aliceShared, bobShared)) {
                System.out.println("Key exchange successful!");
            } else {
                System.out.println("Key exchange failed!");
            }

        } catch (InvalidKeyException e) {
            System.err.println("Key exchange failed: " + e.getMessage());
        }
    }
}


class DiffieHellmanExample {
    public void performKeyExchange() {
        try {
            BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
                    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
                    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
            BigInteger g = BigInteger.valueOf(2);

            KeyPairGenerator aliceKeyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);
            aliceKeyPairGen.initialize(dhSpec);
            KeyPair aliceKeyPair = aliceKeyPairGen.generateKeyPair();

            KeyPairGenerator bobKeyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            bobKeyPairGen.initialize(dhSpec);
            KeyPair bobKeyPair = bobKeyPairGen.generateKeyPair();

            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DiffieHellman");
            aliceKeyAgree.init(aliceKeyPair.getPrivate());

            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DiffieHellman");
            bobKeyAgree.init(bobKeyPair.getPrivate());

            aliceKeyAgree.doPhase(bobKeyPair.getPublic(), true);
            bobKeyAgree.doPhase(aliceKeyPair.getPublic(), true);

            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            byte[] bobSharedSecret = bobKeyAgree.generateSecret();

            System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(aliceSharedSecret));
            System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bobSharedSecret));

            if (MessageDigest.isEqual(aliceSharedSecret, bobSharedSecret)) {
                System.out.println("Shared secrets match!");
            } else {
                System.out.println("Shared secrets do not match.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class ECDiffieHellmanExample {
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

            aliceKeyAgree.doPhase(bobKeyPair.getPublic(), true);
            bobKeyAgree.doPhase(aliceKeyPair.getPublic(), true);

            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            byte[] bobSharedSecret = bobKeyAgree.generateSecret();

            System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(aliceSharedSecret));
            System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bobSharedSecret));

            if (MessageDigest.isEqual(aliceSharedSecret, bobSharedSecret)) {
                System.out.println("Shared secrets match!");
            } else {
                System.out.println("Shared secrets do not match.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class ManualDiffieHellman {
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
    private static final BigInteger G = BigInteger.valueOf(2);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private final SecureRandom secureRandom;

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
            BigInteger numerator = p2.y.subtract(p1.y);
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

        // y² = x³ + ax + b
        BigInteger left = point.y.pow(2).mod(P);
        BigInteger right = point.x.pow(3).add(A.multiply(point.x)).add(B).mod(P);
        return left.equals(right);
    }

    private byte[] deriveKey(byte[] sharedSecret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(sharedSecret);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}