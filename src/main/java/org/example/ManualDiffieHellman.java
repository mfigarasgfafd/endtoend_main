package org.example;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;



public class ManualDiffieHellman {
    // Predefined groups by key size
    private static final Map<Integer, Group> predefinedGroups = new HashMap<>();
    static {

        // 1024-bit MODP Group 2 (RFC 2409)
        BigInteger p1024 = new BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                        "FFFFFFFFFFFFFFFF", 16);
        predefinedGroups.put(1024, new Group(p1024, BigInteger.valueOf(2)));


        // 2048-bit group (RFC 3526, Group 14)
        BigInteger p2048 = new BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                        "FFFFFFFFFFFFFFFF", 16);
        BigInteger g2048 = BigInteger.valueOf(2);
        predefinedGroups.put(2048, new Group(p2048, g2048));

        // 3072-bit group (RFC 3526, Group 15)
        BigInteger p3072 = new BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
                        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
                        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
                        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
                        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
                        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);
        BigInteger g3072 = BigInteger.valueOf(2);
        predefinedGroups.put(3072, new Group(p3072, g3072));


        // 8192-bit group (RFC 7919, Group 18)
        predefinedGroups.put(8192, new Group(new BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
                        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
                        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
                        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
                        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
                        "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
                        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
                        "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
                        "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
                        "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
                        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
                        "FFFFFFFFFFFFFFFF", 16),
                BigInteger.valueOf(2)));


        // 7680-bit prime (generated via OpenSSL)
//        BigInteger p7680 = new BigInteger(
//                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
//                        // ... truncated for brevity ...
//                        "FFFFFFFFFFFFFFFF", 16);
//        predefinedGroups.put(7680, new Group(p7680, BigInteger.valueOf(2)));

    }

    private static class Group {
        final BigInteger P;
        final BigInteger G;
        final BigInteger Q;  // Subgroup order = (P-1)/2

        Group(BigInteger P, BigInteger G) {
            this.P = P;
            this.G = G;
            this.Q = P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        }
    }

    private Group group;  // Current group parameters
    private final SecureRandom rnd = new SecureRandom();
    private BigInteger a;     // Private exponent
    private BigInteger A;     // Public value g^a mod p
    private byte[] shared;    // Derived key

    public ManualDiffieHellman() {
        this.group = predefinedGroups.get(2048);  // Default to 2048-bit
    }

    /**
     * Set key size using predefined groups (2048 or 3072 bits).
     * @param keySize Desired key size (2048 or 3072)
     * @throws IllegalArgumentException for unsupported sizes
     */
    public void setKeySize(int keySize) {
        if (!predefinedGroups.containsKey(keySize)) {
            throw new IllegalArgumentException("Unsupported key size. Use 1024, 2048 or 3072, 7680 ");
        }
        this.group = predefinedGroups.get(keySize);
    }

    /**
     * Set custom Diffie-Hellman parameters.
     * @param P Prime modulus
     * @param G Generator
     */
    public void setGroup(BigInteger P, BigInteger G) {
        this.group = new Group(P, G);
    }

    public void initialize() {
        BigInteger two = BigInteger.valueOf(2);
        BigInteger max = group.P.subtract(two);
        do {
            a = new BigInteger(group.P.bitLength(), rnd);
        } while (a.compareTo(two) < 0 || a.compareTo(max) > 0);

        BigInteger k = new BigInteger(group.Q.bitLength(), rnd);
        BigInteger exp = a.add(k.multiply(group.Q));
        A = group.G.modPow(exp, group.P);
    }

    public void computeSharedSecret(BigInteger B) throws InvalidKeyException {
        if (B.compareTo(BigInteger.TWO) < 0 ||
                B.compareTo(group.P.subtract(BigInteger.TWO)) > 0 ||
                !B.modPow(group.Q, group.P).equals(BigInteger.ONE)) {
            throw new InvalidKeyException("Invalid public key");
        }

        BigInteger k = new BigInteger(group.Q.bitLength(), rnd);
        BigInteger exp = a.add(k.multiply(group.Q));
        BigInteger s = B.modPow(exp, group.P);

        if (!s.modPow(group.Q, group.P).equals(BigInteger.ONE)) {
            throw new InvalidKeyException("Invalid shared secret");
        }

        byte[] ikm = toFixed(s);
        byte[] salt = null;
        byte[] info = "DH shared secret".getBytes();
        shared = hkdfSha256(ikm, salt, info, 32);
    }

    public BigInteger getPublicKey() {
        return A;
    }

    public byte[] getSharedSecret() {
        return shared;
    }

    public BigInteger getPrivateKey() {
        return a;
    }

    private byte[] toFixed(BigInteger v) {
        int byteLength = (group.P.bitLength() + 7) / 8;
        byte[] b = v.toByteArray();
        if (b.length > byteLength) {
            byte[] tmp = new byte[byteLength];
            System.arraycopy(b, b.length - byteLength, tmp, 0, byteLength);
            return tmp;
        } else if (b.length < byteLength) {
            byte[] tmp = new byte[byteLength];
            System.arraycopy(b, 0, tmp, byteLength - b.length, b.length);
            return tmp;
        }
        return b;
    }

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



}
