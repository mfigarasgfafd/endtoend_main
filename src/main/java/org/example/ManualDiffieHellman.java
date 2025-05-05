package org.example;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

public class ManualDiffieHellman {
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
    private static final BigInteger G = BigInteger.valueOf(2);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private final SecureRandom secureRandom;
    private byte[] sharedSecret;
    private BigInteger privateKey;
    private BigInteger publicKey;

    public ManualDiffieHellman() {
        this.secureRandom = new SecureRandom();
    }

    public void initialize() {
        this.privateKey = generatePrivateKey();
        this.publicKey = generatePublicKey(privateKey);
    }


    public void computeSharedSecret(BigInteger partnerPublicKey) throws InvalidKeyException {
        if (!isValidPublicKey(partnerPublicKey)) {
            throw new InvalidKeyException("Invalid public key");
        }

        BigInteger shared = partnerPublicKey.modPow(privateKey, P);
        if (!isValidSharedSecret(shared)) {
            throw new InvalidKeyException("Invalid shared secret");
        }

        this.sharedSecret = deriveKey(shared.toByteArray());
    }

    public String getPublicKey() {
        return publicKey.toString();
    }

    public BigInteger getPrivateKey() {
        return this.privateKey;
    }
    public byte[] getSharedSecret() {
        return sharedSecret;
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



    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }
}
