package org.example;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.Stage;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainGUI extends Application {
    private ManualDiffieHellman manualDhAlice;
    private ManualDiffieHellman manualDhBob;
    private ManualECDiffieHellman alice;
    private ManualECDiffieHellman bob;

    private DiffieHellmanExample dhExample;
    private ECDiffieHellmanExample ecDhExample;
    private ManualECDiffieHellman manualEcdhAlice;

    private ListView<String> chatList;
    private TextField messageInput;
    private ChoiceBox<String> algorithmChoice;

    private ObservableList<String> chatMessages = FXCollections.observableArrayList();


    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("endtoend chat");

        // Initialize chat messages list first
        chatMessages = FXCollections.observableArrayList();

        // Main container
        BorderPane root = new BorderPane();
        root.getStyleClass().add("root");

        // Left sidebar with contacts
        VBox contactsPanel = createContactsPanel();
        root.setLeft(contactsPanel);

        // Main chat area
        VBox chatContainer = createChatContainer();
        root.setCenter(chatContainer);

        chatList.setItems(chatMessages);

        Scene scene = new Scene(root, 800, 600);
        scene.getStylesheets().add(getClass().getClassLoader().getResource("styles.css").toExternalForm());
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void addMessageToChat(String message, boolean isUserMessage) {
        String formattedMessage = (isUserMessage ? "You: " : "System: ") + message;
        Platform.runLater(() -> {
            chatMessages.add(formattedMessage);
            chatList.scrollTo(chatMessages.size() - 1);
        });
    }

    private VBox createContactsPanel() {
        VBox contactsPanel = new VBox();
        contactsPanel.getStyleClass().add("contacts-panel");

        Label contactsHeader = new Label("Contacts");
        contactsHeader.getStyleClass().add("contacts-header");

        HBox aliceContact = new HBox(10);
        aliceContact.getStyleClass().add("contact-item");
        Circle statusIndicator = new Circle(5, Color.LIMEGREEN);
        Label aliceName = new Label("Alice (Server)");
        aliceName.getStyleClass().add("contact-name");
        aliceContact.getChildren().addAll(statusIndicator, aliceName);

        contactsPanel.getChildren().addAll(contactsHeader, aliceContact);
        return contactsPanel;
    }

    private VBox createChatContainer() {
        VBox chatContainer = new VBox();
        chatContainer.getStyleClass().add("chat-container");

        // Chat header
        HBox chatHeader = new HBox(10);
        chatHeader.getStyleClass().add("chat-header");
        Label chatTitle = new Label("Alice");
        chatTitle.getStyleClass().add("chat-title");

        HBox controls = new HBox(10);
        algorithmChoice = new ChoiceBox<>();
        algorithmChoice.getItems().addAll("Diffie-Hellman", "ECDH", "Manual DH", "Manual ECDH");
        algorithmChoice.setValue("Manual ECDH");
        algorithmChoice.getStyleClass().add("algorithm-choice");

        Button startExchangeBtn = new Button("Start Key Exchange");
        startExchangeBtn.getStyleClass().add("exchange-btn");
        startExchangeBtn.setOnAction(e -> startKeyExchange());

        controls.getChildren().addAll(
                new Label("Algorithm:"), algorithmChoice, startExchangeBtn
        );

        chatHeader.getChildren().addAll(chatTitle, controls);

        // chat
        chatList = new ListView<>();
        chatList.getStyleClass().add("chat-list");
        VBox.setVgrow(chatList, Priority.ALWAYS); // proper sizing
        chatList.setCellFactory(param -> new MessageCell());

        // Message input area
        HBox messageBox = new HBox(10);
        messageBox.getStyleClass().add("message-box");


        messageInput = new TextField();
        messageInput.setPromptText("Type your message...");
        messageInput.getStyleClass().add("message-input");

        Button sendBtn = new Button("Send");
        sendBtn.getStyleClass().add("send-btn");
        sendBtn.setOnAction(e -> sendMessage());

        messageBox.getChildren().addAll(messageInput, sendBtn);

        chatContainer.getChildren().addAll(chatHeader, chatList, messageBox);
        return chatContainer;
    }


    private static class MessageCell extends ListCell<String> {
        private final Label messageLabel = new Label();
        private final HBox container = new HBox();
        private final Region spacer = new Region();

        public MessageCell() {
            super();
            container.setMaxWidth(Double.MAX_VALUE);
            HBox.setHgrow(spacer, Priority.ALWAYS);

            messageLabel.setWrapText(true);
            messageLabel.setMaxWidth(300);
            messageLabel.setPadding(new Insets(8));
            messageLabel.getStyleClass().add("message-bubble");
        }
        @Override
        protected void updateItem(String message, boolean empty) {
            super.updateItem(message, empty);
            setText(null);

            if (empty || message == null) {
                setGraphic(null);
            } else {
                messageLabel.setText(message);
                if (message.startsWith("You:")) {
                    messageLabel.getStyleClass().add("sent-message");
                    container.getChildren().setAll(spacer, messageLabel);
                } else {
                    messageLabel.getStyleClass().add("received-message");
                    container.getChildren().setAll(messageLabel, spacer);
                }
                setGraphic(container);
            }
        }
    }



    private void startKeyExchange() {
        String algorithm = algorithmChoice.getValue();

        // Wrap UI updates in Platform.runLater
        Platform.runLater(() -> chatMessages.clear());

        new Thread(() -> {
            try {
//            chatMessages.clear();
                switch (algorithm) {
                    case "Diffie-Hellman":
                        dhExample = new DiffieHellmanExample();
                        dhExample.performKeyExchange();
                        Platform.runLater(() ->
                                addMessageToChat("DH Key Exchange Completed", false));
                        break;
                    case "ECDH":
                        ecDhExample = new ECDiffieHellmanExample();
                        ecDhExample.performKeyExchange();
                        Platform.runLater(() ->
                                addMessageToChat("ECDH Key Exchange Completed", false));
                        break;
                    case "Manual DH":
                        runManualDH();
                        break;
                    case "Manual ECDH":
                        runManualECDH();
                        break;
                }
            }catch(Exception e) {
                Platform.runLater(() ->
                        addMessageToChat("Error: " + e.getMessage(), false));
            }

        }).start();
    }

    private void runManualDH() {
        try {
            manualDhAlice = new ManualDiffieHellman();
            ManualDiffieHellman bob = new ManualDiffieHellman();

            BigInteger alicePrivate = manualDhAlice.generatePrivateKey();
            BigInteger bobPrivate = bob.generatePrivateKey();

            BigInteger alicePublic = manualDhAlice.generatePublicKey(alicePrivate);
            BigInteger bobPublic = bob.generatePublicKey(bobPrivate);

            byte[] aliceShared = manualDhAlice.computeSharedSecret(alicePrivate, bobPublic);
            byte[] bobShared = bob.computeSharedSecret(bobPrivate, alicePublic);

            manualDhAlice.setSharedSecret(aliceShared);

            addMessageToChat("Manual DH Successful!", false);
        } catch (Exception e) {
            addMessageToChat("Manual DH Failed: " + e.getMessage(), false);
        }
    }

    private void runManualECDH() {
        try {
            manualEcdhAlice = new ManualECDiffieHellman();
            ManualECDiffieHellman bob = new ManualECDiffieHellman();

            manualEcdhAlice.generateKeyPair();
            bob.generateKeyPair();

            manualEcdhAlice.computeSharedSecret(bob.getPublicKey());
            bob.computeSharedSecret(manualEcdhAlice.getPublicKey());

            addMessageToChat("Manual ECDH Successful!", false);
        } catch (Exception e) {
            addMessageToChat("Manual ECDH Failed: " + e.getMessage(), false);
        }
    }




    private void sendMessage() {
        String message = messageInput.getText();
        if (!message.isEmpty()) {
            try {
                // Use existing shared secret from key exchange
                byte[] sharedSecret = null;
                String algorithm = algorithmChoice.getValue();

                switch (algorithm) {
                    case "Diffie-Hellman":
                        if (dhExample != null) {
                            sharedSecret = dhExample.getSharedSecret();
                        }
                        break;

                    case "ECDH":
                        if (ecDhExample != null) {
                            sharedSecret = ecDhExample.getSharedSecret();
                        }
                        break;

                    case "Manual DH":
                        if (manualDhAlice != null) {
                            sharedSecret = manualDhAlice.getSharedSecret();
                        }
                        break;

                    case "Manual ECDH":
                        if (manualEcdhAlice != null) {
                            sharedSecret = manualEcdhAlice.getSharedSecret();
                        }
                        break;
                }

                if (sharedSecret == null) {
                    System.err.println("Perform key exchange first!");
                    return;
                }

                // Derive AES key from the PRE-COMPUTED shared secret
                SecretKey aesKey = deriveAESKey(sharedSecret);

                // Encrypt and display
                byte[] encrypted = encryptMessage(message, aesKey);
                String encryptedB64 = Base64.getEncoder().encodeToString(encrypted);
                addMessageToChat("Encrypted: " + encryptedB64, false);


                // Decrypt and display
                String decrypted = decryptMessage(encrypted, aesKey);
                addMessageToChat("Decrypted: " + decrypted, false);

                messageInput.clear();
            } catch (Exception e) {
                addMessageToChat("Error: " + e.getMessage(), false);
            }
        }
    }

    private SecretKey deriveAESKey(byte[] sharedSecret) {
        try {
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(sharedSecret, null, null));

            byte[] aesKeyBytes = new byte[32]; // 256-bit key
            hkdf.generateBytes(aesKeyBytes, 0, aesKeyBytes.length);

            return new SecretKeySpec(aesKeyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }

    private static final int GCM_IV_LENGTH = 12; // 96 bits for GCM
    private static final int GCM_TAG_LENGTH = 16 * 8; // 128-bit authentication tag

    private byte[] encryptMessage(String message, SecretKey key) throws GeneralSecurityException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ciphertext = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Combine IV + ciphertext
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);
        return byteBuffer.array();
    }

    private String decryptMessage(byte[] encrypted, SecretKey key) throws GeneralSecurityException {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);

        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);

        byte[] ciphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted, StandardCharsets.UTF_8);
    }


}