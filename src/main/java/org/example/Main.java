package org.example;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {
        System.out.println("--- Diffie-Hellman Key Exchange ---");
        DiffieHellmanExample dhExample = new DiffieHellmanExample();
        dhExample.performKeyExchange();

        System.out.println("\n--- Elliptic Curve Diffie-Hellman Key Exchange ---");
        ECDiffieHellmanExample ecDhExample = new ECDiffieHellmanExample();
        ecDhExample.performKeyExchange();

        System.out.println("\n--- Manual Diffie-Hellman Key Exchange ---");
        ManualDiffieHellman manualDH = new ManualDiffieHellman();
        manualDH.performKeyExchange();

        System.out.println("\n--- Manual Elliptic Curve Diffie-Hellman Key Exchange ---");
        ManualECDiffieHellman manualECDH = new ManualECDiffieHellman();
        manualECDH.performKeyExchange();
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
    public void performKeyExchange() {
        try {
            BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
                    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
                    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
            BigInteger g = BigInteger.valueOf(2);

            SecureRandom random = new SecureRandom();
            BigInteger alicePrivate = new BigInteger(p.bitLength() - 1, random);
            BigInteger bobPrivate = new BigInteger(p.bitLength() - 1, random);

            BigInteger alicePublic = g.modPow(alicePrivate, p);
            BigInteger bobPublic = g.modPow(bobPrivate, p);

            BigInteger aliceSharedSecret = bobPublic.modPow(alicePrivate, p);
            BigInteger bobSharedSecret = alicePublic.modPow(bobPrivate, p);

            System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(aliceSharedSecret.toByteArray()));
            System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bobSharedSecret.toByteArray()));

            if (aliceSharedSecret.equals(bobSharedSecret)) {
                System.out.println("Shared secrets match!");
            } else {
                System.out.println("Shared secrets do not match.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class ManualECDiffieHellman {
    public void performKeyExchange() {
        try {
            BigInteger a = new BigInteger("3");
            BigInteger b = new BigInteger("-3");
            BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16);
            BigInteger gx = new BigInteger("5");
            BigInteger gy = new BigInteger("1");

            SecureRandom random = new SecureRandom();
            BigInteger alicePrivate = new BigInteger(p.bitLength() - 1, random);
            BigInteger bobPrivate = new BigInteger(p.bitLength() - 1, random);

            BigInteger alicePublic = gx.modPow(alicePrivate, p);
            BigInteger bobPublic = gx.modPow(bobPrivate, p);

            BigInteger aliceSharedSecret = bobPublic.modPow(alicePrivate, p);
            BigInteger bobSharedSecret = alicePublic.modPow(bobPrivate, p);

            System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(aliceSharedSecret.toByteArray()));
            System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bobSharedSecret.toByteArray()));

            if (aliceSharedSecret.equals(bobSharedSecret)) {
                System.out.println("Shared secrets match!");
            } else {
                System.out.println("Shared secrets do not match.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
