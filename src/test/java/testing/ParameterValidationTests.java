package testing;

import org.example.ManualDiffieHellman;
import org.example.ManualECDiffieHellman;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertThrows;

class ParameterValidationTests {

    // ================= MANUAL IMPLEMENTATION TESTS =================

    @Test
    @DisplayName("Manual DH-2048: B = 1 should be rejected")
    void manualDhPublicKeyOne() throws Exception {
        ManualDiffieHellman dh = new ManualDiffieHellman();
        dh.setKeySize(2048);
        dh.initialize();

        assertThrows(InvalidKeyException.class, () ->
                dh.computeSharedSecret(BigInteger.ONE));
    }

    @Test
    @DisplayName("Manual DH-2048: B = p-1 should be rejected")
    void manualDhPublicKeyPMinusOne() throws Exception {
        ManualDiffieHellman dh = new ManualDiffieHellman();
        dh.setKeySize(2048);
        dh.initialize();

        // Get prime modulus (p)
        BigInteger p = getDhPrimeModulus(dh);
        BigInteger invalidKey = p.subtract(BigInteger.ONE);

        assertThrows(InvalidKeyException.class, () ->
                dh.computeSharedSecret(invalidKey));
    }

    @Test
    @DisplayName("Manual ECDH-P256: Point not on curve should be rejected")
    void manualEcdhPointNotOnCurve() throws Exception {
        ManualECDiffieHellman ecdh = new ManualECDiffieHellman();
        ecdh.generateKeyPair();

        // Valid x-coordinate but invalid y-coordinate
        BigInteger x = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
        BigInteger y = BigInteger.ZERO;  // Invalid y-coordinate
        ManualECDiffieHellman.ECPointAffine invalidPoint =
                new ManualECDiffieHellman.ECPointAffine(x, y);

        assertThrows(InvalidKeyException.class, () ->
                ecdh.computeSharedSecret(invalidPoint));
    }

    @Test
    @DisplayName("Manual ECDH-P256: Point at infinity should be rejected")
    void manualEcdhPointAtInfinity() throws Exception {
        ManualECDiffieHellman ecdh = new ManualECDiffieHellman();
        ecdh.generateKeyPair();

        ManualECDiffieHellman.ECPointAffine infinity =
                new ManualECDiffieHellman.ECPointAffine();  // Point at infinity

        assertThrows(InvalidKeyException.class, () ->
                ecdh.computeSharedSecret(infinity));
    }

    // Helper to get DH prime modulus through reflection
    private BigInteger getDhPrimeModulus(ManualDiffieHellman dh) throws Exception {
        java.lang.reflect.Field groupField = ManualDiffieHellman.class.getDeclaredField("group");
        groupField.setAccessible(true);
        Object group = groupField.get(dh);

        java.lang.reflect.Field pField = group.getClass().getDeclaredField("P");
        pField.setAccessible(true);
        return (BigInteger) pField.get(group);
    }

    // ================= JCA IMPLEMENTATION TESTS =================

    @Test
    @DisplayName("JCA DH-2048: B = 1 should be rejected")
    void jcaDhPublicKeyOne() throws Exception {
        // Setup
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
        KeyPair aliceKeyPair = kpg.generateKeyPair();

        // Create invalid public key (1)
        BigInteger p = ((javax.crypto.interfaces.DHPublicKey) aliceKeyPair.getPublic()).getParams().getP();
        BigInteger g = ((javax.crypto.interfaces.DHPublicKey) aliceKeyPair.getPublic()).getParams().getG();
        javax.crypto.spec.DHPublicKeySpec invalidSpec = new javax.crypto.spec.DHPublicKeySpec(
                BigInteger.ONE, p, g
        );
        PublicKey invalidPublic = KeyFactory.getInstance("DH").generatePublic(invalidSpec);

        // Test
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(aliceKeyPair.getPrivate());
        assertThrows(InvalidKeyException.class, () ->
                ka.doPhase(invalidPublic, true));
    }

    @Test
    @DisplayName("JCA DH-2048: B = p-1 should be rejected")
    void jcaDhPublicKeyPMinusOne() throws Exception {
        // Setup
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
        KeyPair aliceKeyPair = kpg.generateKeyPair();

        // Create invalid public key (p-1)
        javax.crypto.interfaces.DHPublicKey pubKey = (javax.crypto.interfaces.DHPublicKey) aliceKeyPair.getPublic();
        BigInteger p = pubKey.getParams().getP();
        BigInteger g = pubKey.getParams().getG();
        javax.crypto.spec.DHPublicKeySpec invalidSpec = new javax.crypto.spec.DHPublicKeySpec(
                p.subtract(BigInteger.ONE), p, g
        );
        PublicKey invalidPublic = KeyFactory.getInstance("DH").generatePublic(invalidSpec);

        // Test
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(aliceKeyPair.getPrivate());
        assertThrows(InvalidKeyException.class, () ->
                ka.doPhase(invalidPublic, true));
    }

    @Test
    @DisplayName("JCA ECDH-P256: Point not on curve should be rejected")
    void jcaEcdhPointNotOnCurve() throws Exception {
        // Setup
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair aliceKeyPair = kpg.generateKeyPair();

        // Create invalid point (valid x, invalid y)
        ECPoint invalidPoint = new ECPoint(
                new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
                BigInteger.ZERO  // Invalid y-coordinate
        );
        PublicKey invalidPublic = createInvalidEcPublicKey(aliceKeyPair, invalidPoint);

        // Test
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(aliceKeyPair.getPrivate());
        assertThrows(InvalidKeyException.class, () ->
                ka.doPhase(invalidPublic, true));
    }

    @Test
    @DisplayName("JCA ECDH-P256: Point at infinity should be rejected")
    void jcaEcdhPointAtInfinity() throws Exception {
        // Setup
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair aliceKeyPair = kpg.generateKeyPair();

        // Create a valid public key that we'll modify to return POINT_INFINITY
        ECPublicKey validKey = (ECPublicKey) aliceKeyPair.getPublic();
        ECPublicKey mockKey = new ECPublicKey() {
            @Override
            public ECPoint getW() {
                return ECPoint.POINT_INFINITY;
            }

            @Override
            public String getAlgorithm() { return "EC"; }
            @Override
            public String getFormat() { return "X.509"; }
            @Override
            public byte[] getEncoded() { return validKey.getEncoded(); }
            @Override
            public java.security.spec.ECParameterSpec getParams() {
                return validKey.getParams();
            }
        };

        // Test
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(aliceKeyPair.getPrivate());
        assertThrows(InvalidKeyException.class, () ->
                ka.doPhase(mockKey, true));
    }

    // Helper to create invalid EC public key
    private PublicKey createInvalidEcPublicKey(KeyPair validKeyPair, ECPoint point)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        java.security.interfaces.ECPublicKey ecPubKey =
                (java.security.interfaces.ECPublicKey) validKeyPair.getPublic();

        ECPublicKeySpec invalidSpec = new ECPublicKeySpec(
                point,
                ecPubKey.getParams()
        );
        return KeyFactory.getInstance("EC").generatePublic(invalidSpec);
    }
}