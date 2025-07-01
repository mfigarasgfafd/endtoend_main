package org.example;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class ManualECDiffieHellman {
    // Instance curve parameters (default secp256r1)
    private static BigInteger P;
    private static BigInteger A;
    private BigInteger B;
    private BigInteger N;
    private ECPointJacobian G;

    // Instance state
    private BigInteger d;
    private ECPointAffine Q;
    private byte[] shared;
    private int keySize = 256; // Default key size

    private final SecureRandom rnd = new SecureRandom();
    private PointArithmeticWorkspace workspace;

    // ===== HKDF reuse fields =====
    private static final Mac HKDF_MAC;
    static {
        try {
            HKDF_MAC = Mac.getInstance("HmacSHA256");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private byte[] saltBytes;    // all-zero salt
    private byte[] prkBytes;     // holds PRK
    private byte[] tBytes;       // temp buffer
    private byte[] okmBytes;     // output keying material
    private SecretKeySpec saltKeySpec;
    private SecretKeySpec prkKeySpec;

    public ManualECDiffieHellman() throws InvalidKeyException {
        setKeySize(256); // Initialize with default curve
    }

    public void setKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 160 && keySize != 256 && keySize != 384 && keySize != 512) {
            throw new InvalidKeyException("Unsupported key size. Use 160, 256, 384, or 512.");
        }
        this.keySize = keySize;
        resetState();
        initializeCurve();
        initializeBuffers();
        workspace = new PointArithmeticWorkspace(P);
    }

    private void resetState() {
        d = null;
        Q = null;
        shared = null;
    }

    private void initializeCurve() throws InvalidKeyException {
        switch (keySize) {
            case 160:
                P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", 16);
                A = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", 16);
                B = new BigInteger("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", 16);
                N = new BigInteger("100000000000000000001F4C8F927AED3CA752257", 16);
                G = new ECPointJacobian(
                        new BigInteger("4A96B5688EF573284664698968C38BB913CBFC82", 16),
                        new BigInteger("23A628553168947D59DCC912042351377AC5FB32", 16),
                        BigInteger.ONE
                );
                break;
            case 256:
                P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
                A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
                B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
                N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
                G = new ECPointJacobian(
                        new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
                        new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
                        BigInteger.ONE
                );
                break;
            case 384:
                P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16);
                A = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16);
                B = new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16);
                N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16);
                G = new ECPointJacobian(
                        new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
                        new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16),
                        BigInteger.ONE
                );
                break;
            case 512: // secp521r1
                P = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
                A = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16);
                B = new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16);
                N = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16);
                G = new ECPointJacobian(
                        new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
                        new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16),
                        BigInteger.ONE
                );
                break;
            default:
                throw new InvalidKeyException("Unsupported key size");
        }
    }

    private void initializeBuffers() {
        int numBytes = (P.bitLength() + 7) / 8;
        saltBytes = new byte[numBytes]; // all-zero salt
        prkBytes = new byte[32]; // PRK always 32 bytes for HmacSHA256
        tBytes = new byte[32]; // temp buffer for HKDF
        okmBytes = new byte[32]; // output fixed at 32 bytes
        saltKeySpec = new SecretKeySpec(saltBytes, "HmacSHA256");
        prkKeySpec = new SecretKeySpec(prkBytes, "HmacSHA256");
    }

    public void generateKeyPair() throws InvalidKeyException {
        // 1) random scalar in [1, N-1]
        do {
            d = new BigInteger(N.bitLength(), rnd);
        } while (d.compareTo(BigInteger.ONE) < 0 || d.compareTo(N) >= 0);

        // 2) compute Q = d·G
        workspace.reset();
        ECPointJacobian R = scalarMult(G, d);
        Q = R.toAffine();

        // 3) sanity check
        if (!isOnCurve(Q)) {
            throw new InvalidKeyException("Invalid public key");
        }
    }

    public void computeSharedSecret(ECPointAffine Ppub) throws InvalidKeyException {
        if (!isOnCurve(Ppub)) {
            throw new InvalidKeyException("Peer public key not on curve");
        }

        workspace.reset();
        ECPointJacobian R = scalarMult(Ppub.toJacobian(), d);
        if (R.isInfinity()) {
            throw new InvalidKeyException("Result is point at infinity");
        }

        ECPointAffine S = R.toAffine();
        int numBytes = (P.bitLength() + 7) / 8;
        byte[] ikm = toBytes(S.x, numBytes);
        shared = hkdfSha256(ikm, null, "ECDH shared secret".getBytes(), 32);
    }

    public byte[] getSharedSecret() {
        return shared;
    }

    public byte[] getPrivateKeyBytes() {
        int numBytes = (P.bitLength() + 7) / 8;
        return toBytes(d, numBytes);
    }

    public byte[] getPublicKeyBytes() {
        int numBytes = (P.bitLength() + 7) / 8;
        byte[] xb = toBytes(Q.x, numBytes);
        byte[] yb = toBytes(Q.y, numBytes);
        byte[] o  = new byte[1 + 2 * numBytes];
        o[0] = 4; // Uncompressed format
        System.arraycopy(xb, 0, o, 1, numBytes);
        System.arraycopy(yb, 0, o, 1 + numBytes, numBytes);
        return o;
    }

    // ================= Scalar multiplication (Montgomery ladder style) ================
    private ECPointJacobian scalarMult(ECPointJacobian P, BigInteger k) {
        workspace.R0.set(ECPointJacobian.INF);
        workspace.R1.set(P);

        for (int i = k.bitLength() - 1; i >= 0; i--) {
            if (k.testBit(i)) {
                // R0 = R0 + R1;  R1 = 2*R1
                workspace.R0.add(workspace.R1, workspace.T0, workspace.modArith);
                workspace.R1.twice(workspace.T1, workspace.modArith);
            } else {
                // R1 = R1 + R0;  R0 = 2*R0
                workspace.R1.add(workspace.R0, workspace.T0, workspace.modArith);
                workspace.R0.twice(workspace.T1, workspace.modArith);
            }
            workspace.R0.set(workspace.T0);
            workspace.R1.set(workspace.T1);
        }
        return workspace.R0;
    }

    private boolean isOnCurve(ECPointAffine pt) {
        if (pt.infinity) return false;
        BigInteger y2 = workspace.modArith.square(pt.y);
        BigInteger x3 = workspace.modArith.multiply(pt.x, pt.x).multiply(pt.x).mod(P);
        BigInteger ax = workspace.modArith.multiply(A, pt.x);
        BigInteger rhs = workspace.modArith.add(workspace.modArith.add(x3, ax), B);
        return y2.equals(rhs);
    }

    // ================= HKDF-SHA256 (reuse buffers) =================
    private byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            // --- Extract ---
            HKDF_MAC.init((salt == null)
                    ? saltKeySpec
                    : new SecretKeySpec(salt, "HmacSHA256"));
            // feed IKM
            HKDF_MAC.update(ikm);
            // get PRK
            byte[] prk = HKDF_MAC.doFinal();
            // copy into prkBytes buffer
            System.arraycopy(prk, 0, prkBytes, 0, prkBytes.length);

            // --- Expand ---
            int pos = 0;
            int counter = 1;
            int tLen = 0;

            while (pos < length) {
                HKDF_MAC.init(prkKeySpec);
                // previous block
                if (tLen > 0) {
                    HKDF_MAC.update(tBytes, 0, tLen);
                }
                // context info
                if (info != null) {
                    HKDF_MAC.update(info);
                }
                // counter octet
                HKDF_MAC.update((byte) counter);
                // compute next T
                byte[] t = HKDF_MAC.doFinal();
                tLen = t.length;
                // copy into reusable tBytes buffer
                System.arraycopy(t, 0, tBytes, 0, tLen);

                // copy as much as needed into okmBytes
                int toCopy = Math.min(tLen, length - pos);
                System.arraycopy(tBytes, 0, okmBytes, pos, toCopy);
                pos += toCopy;
                counter++;
            }

            return okmBytes;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ===== Helper: fixed-length BE representation =====
    private byte[] toBytes(BigInteger v, int numBytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[numBytes];
        int start = (raw.length > numBytes && raw[0] == 0) ? 1 : 0;
        int len = Math.min(raw.length - start, numBytes);
        System.arraycopy(raw, start, out, numBytes - len, len);
        return out;
    }

    // ===== Workspace & Points & ModArithmetic =====
    private static class PointArithmeticWorkspace {
        final ModArithmetic modArith;
        final ECPointJacobian R0 = new ECPointJacobian();
        final ECPointJacobian R1 = new ECPointJacobian();
        final ECPointJacobian T0 = new ECPointJacobian();
        final ECPointJacobian T1 = new ECPointJacobian();

        PointArithmeticWorkspace(BigInteger modulus) {
            modArith = new ModArithmetic(modulus);
        }

        void reset() {
            R0.setInfinity();
            R1.setInfinity();
            T0.setInfinity();
            T1.setInfinity();
        }
    }

    private static class ECPointJacobian {
        BigInteger X, Y, Z;
        boolean infinity;

        static final ECPointJacobian INF = new ECPointJacobian();

        ECPointJacobian() {
            setInfinity();
        }

        ECPointJacobian(BigInteger X, BigInteger Y, BigInteger Z) {
            this.X = X;
            this.Y = Y;
            this.Z = Z;
            this.infinity = false;
        }

        void setInfinity() {
            this.X = BigInteger.ZERO;
            this.Y = BigInteger.ZERO;
            this.Z = BigInteger.ZERO;
            this.infinity = true;
        }

        void set(ECPointJacobian p) {
            this.X = p.X;
            this.Y = p.Y;
            this.Z = p.Z;
            this.infinity = p.infinity;
        }

        boolean isInfinity() {
            return infinity;
        }

        void twice(ECPointJacobian r, ModArithmetic mod) {
            if (infinity) {
                r.setInfinity();
                return;
            }
            BigInteger XX   = mod.square(X);
            BigInteger YY   = mod.square(Y);
            BigInteger YYYY = mod.square(YY);
            BigInteger S    = mod.multiply(BigInteger.valueOf(4), mod.multiply(X, YY));
            BigInteger Z2   = mod.square(Z);
            BigInteger Z4   = mod.square(Z2);
            BigInteger M    = mod.add(mod.multiply(BigInteger.valueOf(3), XX),
                    mod.multiply(A, Z4));

            r.X = mod.subtract(mod.square(M), mod.multiply(BigInteger.valueOf(2), S));
            r.Y = mod.subtract(
                    mod.multiply(M, mod.subtract(S, r.X)),
                    mod.multiply(BigInteger.valueOf(8), YYYY)
            );
            r.Z = mod.multiply(BigInteger.valueOf(2),
                    mod.multiply(Y, Z));
            r.infinity = false;
        }

        void add(ECPointJacobian Q, ECPointJacobian r, ModArithmetic mod) {
            if (infinity) {
                r.set(Q);
                return;
            }
            if (Q.infinity) {
                r.set(this);
                return;
            }

            BigInteger Z1Z1 = mod.square(Z);
            BigInteger Z2Z2 = mod.square(Q.Z);
            BigInteger U1   = mod.multiply(X, Z2Z2);
            BigInteger U2   = mod.multiply(Q.X, Z1Z1);
            BigInteger S1   = mod.multiply(Y, mod.multiply(Q.Z, Z2Z2));
            BigInteger S2   = mod.multiply(Q.Y, mod.multiply(Z, Z1Z1));

            if (U1.equals(U2)) {
                if (S1.equals(S2)) {
                    twice(r, mod);
                    return;
                }
                r.setInfinity();
                return;
            }

            BigInteger H   = mod.subtract(U2, U1);
            BigInteger R_  = mod.subtract(S2, S1);
            BigInteger HH  = mod.square(H);
            BigInteger HHH = mod.multiply(H, HH);
            BigInteger V   = mod.multiply(U1, HH);

            r.X = mod.subtract(mod.subtract(mod.square(R_), HHH),
                    mod.multiply(BigInteger.valueOf(2), V));
            r.Y = mod.subtract(
                    mod.multiply(R_, mod.subtract(V, r.X)),
                    mod.multiply(S1, HHH)
            );
            r.Z = mod.multiply(Z, mod.multiply(Q.Z, H));
            r.infinity = false;
        }

        ECPointAffine toAffine() {
            if (infinity) {
                return ECPointAffine.INF;
            }
            BigInteger zInv  = Z.modInverse(P);
            BigInteger zInv2 = zInv.multiply(zInv).mod(P);
            BigInteger xA    = X.multiply(zInv2).mod(P);
            BigInteger yA    = Y.multiply(zInv2).multiply(zInv).mod(P);
            return new ECPointAffine(xA, yA);
        }
    }

    private static class ModArithmetic {
        private final BigInteger m;
        ModArithmetic(BigInteger modulus) { this.m = modulus; }
        BigInteger add(BigInteger a, BigInteger b)        { return a.add(b).mod(m); }
        BigInteger subtract(BigInteger a, BigInteger b)   { return a.subtract(b).mod(m); }
        BigInteger multiply(BigInteger a, BigInteger b)   { return a.multiply(b).mod(m); }
        BigInteger square(BigInteger a)                   { return a.multiply(a).mod(m); }
    }

    public static class ECPointAffine {
        public final BigInteger x, y;
        public final boolean infinity;
        public static final ECPointAffine INF = new ECPointAffine();

        private ECPointAffine() {
            this.x = this.y = null;
            this.infinity = true;
        }

        public ECPointAffine(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
            this.infinity = false;
        }

        ECPointJacobian toJacobian() {
            return infinity
                    ? new ECPointJacobian()
                    : new ECPointJacobian(x, y, BigInteger.ONE);
        }
    }


    public ECPointAffine getPublicPoint() {
        return Q;
    }
    public String getPublicKey() {
        return bytesToHex(getPublicKeyBytes());
    }
    private String bytesToHex(byte[]b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x));return s.toString();}


}
