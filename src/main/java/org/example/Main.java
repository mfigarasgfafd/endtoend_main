package org.example;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;



public class Main {
    public static void main(String[] args) {

        ChatClient client = new ChatClient();
//        client.initialize("alice", "ECDH"); // or "DH"
//        client.sendMessage("bob", "Secret message");

    }
}


