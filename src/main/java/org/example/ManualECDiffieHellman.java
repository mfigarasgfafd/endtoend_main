package org.example;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
// kompatybilność

public class ManualECDiffieHellman {
    // using curve P-256 parameters (secp256r1)
    private static final BigInteger P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    private static final BigInteger B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final ECPointAffine G = new ECPointAffine(
            new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
            new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
    );

    protected BigInteger d;
    private ECPointAffine Q;
    private byte[] shared;
    private final SecureRandom rnd = new SecureRandom();

    // Generate keypair with subgroup check
    public void generateKeyPair() throws InvalidKeyException {
        // choose private key in [1, N-1]
        do { d = new BigInteger(N.bitLength(), rnd); }
        while (d.compareTo(BigInteger.ONE)<0 || d.compareTo(N.subtract(BigInteger.ONE))>0);
        // compute Q = d*G
        ECPointJacobian R = scalarMult(G.toJacobian(), d);
        ECPointAffine cand = R.toAffine();
        if (!isOnCurve(cand) || !inSubgroup(cand))
            throw new InvalidKeyException("Invalid public key generated");
        Q = cand;
    }

    // compute shared secret and derive via HKDF-SHA256
    public void computeSharedSecret(ECPointAffine Ppub) throws InvalidKeyException {
        if (!isOnCurve(Ppub) || !inSubgroup(Ppub))
            throw new InvalidKeyException("Invalid partner public key");
        ECPointJacobian R = scalarMult(Ppub.toJacobian(), d);
        ECPointAffine S = R.toAffine();
        if (R.isInfinity())
            throw new InvalidKeyException("Shared point at infinity");
        // Derive a 256-bit key using HKDF-SHA256
        byte[] ikm = to32(S.x);
        byte[] salt = null;  // optional salt
        byte[] info = "ECDH shared secret".getBytes();
        this.shared = hkdfSha256(ikm, salt, info, 32);
    }

    public String getPublicKey(){
        byte[] xb=to32(Q.x), yb=to32(Q.y);
        byte[] o=new byte[65]; o[0]=4; System.arraycopy(xb,0,o,1,32); System.arraycopy(yb,0,o,33,32);
        return bytesToHex(o);
    }
    private byte[] to32(BigInteger v){byte[] b=v.toByteArray(); if(b.length==33&&b[0]==0) return Arrays.copyOfRange(b,1,33);
        if(b.length<32){byte[] c=new byte[32];System.arraycopy(b,0,c,32-b.length,b.length);return c;}return b;}
    private String bytesToHex(byte[]b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x));return s.toString();}
    public byte[] getSharedSecret() {
        return shared;
    }

    // ========== PRIVATE HELPERS ===========


    // constant-time Montgomery ladder /w Jacobian coords
    private ECPointJacobian scalarMult(ECPointJacobian Pj, BigInteger k) {
        ECPointJacobian R0 = ECPointJacobian.INF, R1 = Pj;
        for (int i=k.bitLength()-1;i>=0;i--) {
            if (k.testBit(i)) { R0 = R0.add(R1); R1 = R1.twice(); }
            else { R1 = R0.add(R1); R0 = R0.twice(); }
        }
        return R0;
    }

    // validate subgroup: [n]P == infinity
    private boolean inSubgroup(ECPointAffine pt) {
        // check [n]P == INF
        return scalarMult(pt.toJacobian(), N).isInfinity();
    }

    // Curve equation check
    private boolean isOnCurve(ECPointAffine pt) {
        if (pt.infinity) return false;
        BigInteger lhs = pt.y.multiply(pt.y).mod(P);
        BigInteger rhs = pt.x.multiply(pt.x).multiply(pt.x)
                .add(A.multiply(pt.x)).add(B).mod(P);
        return lhs.equals(rhs);
    }

    // ========== HKDF-SHA256 ===========
    private byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            // Extract
            if (salt == null) salt = new byte[32];
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            // Expand
            int hashLen = 32;
            int n = (int) Math.ceil((double) length / hashLen);
            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int copied = 0;
            for (int i = 1; i <= n; i++) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                if (info != null) mac.update(info);
                mac.update((byte) i);
                t = mac.doFinal();
                int toCopy = Math.min(hashLen, length - copied);
                System.arraycopy(t, 0, okm, copied, toCopy);
                copied += toCopy;
            }
            return okm;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ======== COORDINATES =========
    public static class ECPointAffine {
        final BigInteger x,y; final boolean infinity;
        public ECPointAffine(BigInteger x, BigInteger y){this.x=x;this.y=y;this.infinity=false;}
        public ECPointAffine(){this.x=this.y=null;this.infinity=true;}
        public static final ECPointAffine INF=new ECPointAffine();
        ECPointJacobian toJacobian(){return infinity?ECPointJacobian.INF:new ECPointJacobian(x,y,BigInteger.ONE);}
    }

    static class ECPointJacobian {
        final BigInteger X,Y,Z; final boolean infinity;
        ECPointJacobian(BigInteger X,BigInteger Y,BigInteger Z){this.X=X;this.Y=Y;this.Z=Z;this.infinity=false;}
        private ECPointJacobian(){this.X=this.Y=this.Z=null;this.infinity=true;}
        static final ECPointJacobian INF=new ECPointJacobian();
        boolean isInfinity(){return infinity;}

        ECPointJacobian twice(){
            if(infinity) return this;
            // SEC1 Thm 3.21: M = 3*X1^2 + a*Z1^4
            BigInteger XX = X.multiply(X).mod(P);
            BigInteger YY = Y.multiply(Y).mod(P);
            BigInteger YYYY = YY.multiply(YY).mod(P);
            BigInteger S = X.add(YY).multiply(X.add(YY)).subtract(XX).subtract(YYYY)
                    .multiply(BigInteger.valueOf(2)).mod(P);
            BigInteger Z2 = Z.multiply(Z).mod(P);
            BigInteger Z4 = Z2.multiply(Z2).mod(P);
            BigInteger M = XX.multiply(BigInteger.valueOf(3)).add(A.multiply(Z4)).mod(P);
            BigInteger X3 = M.multiply(M).subtract(S).subtract(S).mod(P);
            BigInteger Y3 = M.multiply(S.subtract(X3)).subtract(YYYY.multiply(BigInteger.valueOf(8))).mod(P);
            BigInteger Z3 = Y.multiply(Z).multiply(BigInteger.valueOf(2)).mod(P);
            return new ECPointJacobian(X3,Y3,Z3);
        }
        ECPointJacobian add(ECPointJacobian Q){
            if(this.infinity) return Q; if(Q.infinity) return this;
            BigInteger Z1Z1=Z.multiply(Z).mod(P), Z2Z2=Q.Z.multiply(Q.Z).mod(P);
            BigInteger U1=X.multiply(Z2Z2).mod(P), U2=Q.X.multiply(Z1Z1).mod(P);
            BigInteger Z1Z1Z1=Z.multiply(Z1Z1).mod(P), Z2Z2Z2=Q.Z.multiply(Z2Z2).mod(P);
            BigInteger S1=Y.multiply(Z2Z2Z2).mod(P), S2=Q.Y.multiply(Z1Z1Z1).mod(P);
            if(U1.equals(U2)){
                if(S1.equals(S2)) return twice();
                return INF;
            }
            BigInteger H=U2.subtract(U1).mod(P), R=S2.subtract(S1).mod(P);
            BigInteger HH=H.multiply(H).mod(P), HHH=H.multiply(HH).mod(P);
            BigInteger U1HH=U1.multiply(HH).mod(P);
            BigInteger X3=R.multiply(R).subtract(HHH).subtract(U1HH).subtract(U1HH).mod(P);
            BigInteger Y3=R.multiply(U1HH.subtract(X3)).subtract(S1.multiply(HHH)).mod(P);
            BigInteger Z3=Z.multiply(Q.Z).multiply(H).mod(P);
            return new ECPointJacobian(X3,Y3,Z3);
        }
        ECPointAffine toAffine(){
            if(infinity) return ECPointAffine.INF;
            BigInteger zInv=Z.modInverse(P);
            BigInteger zInv2=zInv.multiply(zInv).mod(P);
            BigInteger xA=X.multiply(zInv2).mod(P);
            BigInteger yA=Y.multiply(zInv2).multiply(zInv).mod(P);
            return new ECPointAffine(xA,yA);
        }
    }


    // ======== INNE UTIL ========
    private byte[] toFixedLength(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length == 33 && b[0] == 0) {
            byte[] tmp = new byte[32];
            System.arraycopy(b, 1, tmp, 0, 32);
            return tmp;
        } else if (b.length < 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(b, 0, tmp, 32 - b.length, b.length);
            return tmp;
        }
        return b;
    }


}