package org.example;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class ManualDiffieHellman {
    // 2048-bit MODP Group 14 prime
    private static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                    "FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger G = BigInteger.valueOf(2);
    // Subgroup order q=(P-1)/2
    private static final BigInteger Q = P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

    private final SecureRandom rnd = new SecureRandom();
    private BigInteger a;     // private exponent
    private BigInteger A;     // public value g^a mod p
    private byte[] shared;    // derived key

    /**
     * Generate key pair.
     */
    public void initialize() {
        // choose a uniformly in [2, P-2]
        BigInteger two = BigInteger.valueOf(2);
        BigInteger max = P.subtract(two);
        do {
            a = new BigInteger(P.bitLength(), rnd);
        } while (a.compareTo(two) < 0 || a.compareTo(max) > 0);

        // blinded exponentiation: compute A = g^(a + kQ) mod P for random k
        BigInteger k = new BigInteger(Q.bitLength(), rnd);
        BigInteger exp = a.add(k.multiply(Q));
        A = G.modPow(exp, P);
    }

    /**
     * Compute shared key from peer's public value B.
     * @param B peer's public value
     * @throws InvalidKeyException if B or the shared secret is invalid
     */
    public void computeSharedSecret(BigInteger B) throws InvalidKeyException {
        // Valid public: 2 <= B <= P-2 and B^Q mod P == 1
        if (B.compareTo(BigInteger.TWO) < 0 || B.compareTo(P.subtract(BigInteger.TWO)) > 0
                || !B.modPow(Q, P).equals(BigInteger.ONE)) {
            throw new InvalidKeyException("Invalid public key");
        }

        // Blinded exponentiation for shared secret
        BigInteger k = new BigInteger(Q.bitLength(), rnd);
        BigInteger exp = a.add(k.multiply(Q));
        BigInteger s = B.modPow(exp, P);

        // Validate s in subgroup: s^Q mod P == 1
        if (!s.modPow(Q, P).equals(BigInteger.ONE)) {
            throw new InvalidKeyException("Invalid shared secret");
        }

        // Derive 32-byte key via HKDF-SHA256
        byte[] ikm = toFixed(s);
        byte[] salt = null; // optional
        byte[] info = "DH shared secret".getBytes();
        shared = hkdfSha256(ikm, salt, info, 32);
    }

    /** @return public key g^a mod p */
    public BigInteger getPublicKey() {
        return A;
    }

    /** @return 32-byte derived shared key */
    public byte[] getSharedSecret() {
        return shared;
    }

    // ======== HKDF-SHA256 Extract-and-Expand ========
    private byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int len) {
        try {
            if (salt == null) salt = new byte[32];
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            int hashLen = 32;
            int n = (len + hashLen - 1) / hashLen;
            byte[] okm = new byte[len];
            byte[] prev = new byte[0];
            int pos = 0;
            for (int i = 1; i <= n; i++) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(prev);
                if (info != null) mac.update(info);
                mac.update((byte) i);
                byte[] out = mac.doFinal();
                int toCopy = Math.min(hashLen, len - pos);
                System.arraycopy(out, 0, okm, pos, toCopy);
                pos += toCopy;
                prev = out;
            }
            return okm;
        } catch (Exception e) {
            throw new RuntimeException("HKDF failed", e);
        }
    }

    // Encode BigInteger to fixed 256-byte array
    private byte[] toFixed(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 256) {
            byte[] tmp = new byte[256];
            System.arraycopy(b, b.length - 256, tmp, 0, 256);
            return tmp;
        } else if (b.length < 256) {
            byte[] tmp = new byte[256];
            System.arraycopy(b, 0, tmp, 256 - b.length, b.length);
            return tmp;
        }
        return b;
    }
}
