package org.example;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;

public class MainGUI extends Application {

    private ChoiceBox<String> algorithmChoice;
    private TextArea chatArea;

    public static void main(String[] args) {
        launch(args);

    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Key Exchange Chat");

        // Create UI components
        VBox root = new VBox(10);
        HBox controls = new HBox(10);

        algorithmChoice = new ChoiceBox<>();
        algorithmChoice.getItems().addAll(
                "Diffie-Hellman",
                "ECDH",
                "Manual DH",
                "Manual ECDH"
        );
        algorithmChoice.setValue("Diffie-Hellman");

        Button startButton = new Button("Start Exchange");
        Button clearButton = new Button("Clear");

        chatArea = new TextArea();
        chatArea.setEditable(false);
        chatArea.setWrapText(true);

        // Redirect console output to chat area
        redirectSystemOutput();

        // Setup button handlers
        startButton.setOnAction(e -> startKeyExchange());
        clearButton.setOnAction(e -> chatArea.clear());

        // Layout setup
        controls.getChildren().addAll(algorithmChoice, startButton, clearButton);
        root.getChildren().addAll(controls, chatArea);

        primaryStage.setScene(new Scene(root, 600, 400));
        primaryStage.show();
    }

    private void redirectSystemOutput() {
        OutputStream out = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                appendToChatArea(String.valueOf((char) b));
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                appendToChatArea(new String(b, off, len));
            }

            private void appendToChatArea(String text) {
                Platform.runLater(() -> chatArea.appendText(text));
            }
        };

        System.setOut(new PrintStream(out, true));
        System.setErr(new PrintStream(out, true));
    }

    private void startKeyExchange() {
        new Thread(() -> {
            String algorithm = algorithmChoice.getValue();
            switch (algorithm) {
                case "Diffie-Hellman":
                    new DiffieHellmanExample().performKeyExchange();
                    break;
                case "ECDH":
                    new ECDiffieHellmanExample().performKeyExchange();
                    break;
                case "Manual DH":
                    runManualDH();
                    break;
                case "Manual ECDH":
                    runManualECDH();
                    break;
            }
        }).start();
    }

    private void runManualDH() {
        try {
            System.out.println("\n--- Manual Diffie-Hellman Key Exchange ---");
            ManualDiffieHellman alice = new ManualDiffieHellman();
            ManualDiffieHellman bob = new ManualDiffieHellman();

            BigInteger alicePrivate = alice.generatePrivateKey();
            BigInteger bobPrivate = bob.generatePrivateKey();

            BigInteger alicePublic = alice.generatePublicKey(alicePrivate);
            BigInteger bobPublic = bob.generatePublicKey(bobPrivate);

            byte[] aliceShared = alice.computeSharedSecret(alicePrivate, bobPublic);
            byte[] bobShared = bob.computeSharedSecret(bobPrivate, alicePublic);

            System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(aliceShared));
            System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bobShared));

            if (Arrays.equals(aliceShared, bobShared)) {
                System.out.println("Key exchange successful!");
            } else {
                System.out.println("Key exchange failed!");
            }
        } catch (InvalidKeyException ex) {
            System.err.println("Key exchange failed: " + ex.getMessage());
        }
    }

    private void runManualECDH() {
        try {
            System.out.println("\n--- Manual Elliptic Curve Diffie-Hellman Key Exchange ---");
            ManualECDiffieHellman alice = new ManualECDiffieHellman();
            ManualECDiffieHellman bob = new ManualECDiffieHellman();

            BigInteger alicePrivate = alice.generatePrivateKey();
            BigInteger bobPrivate = bob.generatePrivateKey();

            ManualECDiffieHellman.ECPoint alicePublic = alice.generatePublicKey(alicePrivate);
            ManualECDiffieHellman.ECPoint bobPublic = bob.generatePublicKey(bobPrivate);

            byte[] aliceShared = alice.computeSharedSecret(alicePrivate, bobPublic);
            byte[] bobShared = bob.computeSharedSecret(bobPrivate, alicePublic);

            System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(aliceShared));
            System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bobShared));

            if (Arrays.equals(aliceShared, bobShared)) {
                System.out.println("Key exchange successful!");
            } else {
                System.out.println("Key exchange failed!");
            }
        } catch (InvalidKeyException ex) {
            System.err.println("Key exchange failed: " + ex.getMessage());
        }
    }


}
