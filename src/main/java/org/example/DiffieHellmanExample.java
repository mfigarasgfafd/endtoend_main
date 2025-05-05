package org.example;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class DiffieHellmanExample {
    private KeyPair keyPair;
    private byte[] sharedSecret;

    public void performKeyExchange(PublicKey partnerPublicKey) throws InvalidKeyException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(2048);
            this.keyPair = kpg.generateKeyPair();

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(partnerPublicKey, true);
            this.sharedSecret = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException e) { // | InvalidAlgorithmParameterException e
            throw new RuntimeException("DH initialization failed", e);
        }
    }

    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}
