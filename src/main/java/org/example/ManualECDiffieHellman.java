package org.example;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ManualECDiffieHellman {
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
        if (!isPointOnCurve(publicKey)) {
            throw new InvalidKeyException("Generated invalid public key");
        }
    }

    public void computeSharedSecret(ECPoint partnerPublicKey) throws InvalidKeyException {
        if (!isPointOnCurve(partnerPublicKey)) {
            throw new InvalidKeyException("Invalid partner public key");
        }

        ECPoint sharedPoint = multiplyPoint(partnerPublicKey, privateKey);
        if (sharedPoint.infinity) {
            throw new InvalidKeyException("Shared point at infinity");
        }

        this.sharedSecret = deriveKey(sharedPoint.x.toByteArray());
    }

    public String getPublicKey() {
        return publicKey.x + "," + publicKey.y;
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
