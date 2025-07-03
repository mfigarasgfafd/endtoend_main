package org.example;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

// testing - unused, library implementation is located in maingui
public class ECDiffieHellmanExample {
    private KeyPair keyPair;
    private byte[] sharedSecret;

    public void performKeyExchange(PublicKey partnerPublicKey) throws InvalidKeyException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            this.keyPair = kpg.generateKeyPair();

            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(partnerPublicKey, true);
            this.sharedSecret = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("ECDH initialization failed", e);
        }
    }

    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}
