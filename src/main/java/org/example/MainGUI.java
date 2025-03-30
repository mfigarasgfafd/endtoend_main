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
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MainGUI extends Application {
    private ManualDiffieHellman manualDhAlice;
    private ManualDiffieHellman manualDhBob;
    private ManualECDiffieHellman alice;
    private ManualECDiffieHellman bob;

    private ListView<String> chatList;
    private TextField messageInput;
    private ChoiceBox<String> algorithmChoice;

    private ObservableList<String> chatMessages = FXCollections.observableArrayList();


    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("SecureChat");

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
            manualDhAlice.setSharedSecret(aliceShared);
            manualDhBob.setSharedSecret(bobShared);
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
            addMessageToChat("Starting Manual ECDH Key Exchange...", false);

            alice = new ManualECDiffieHellman();
            bob = new ManualECDiffieHellman();

            // Generate key pairs
            alice.generateKeyPair();
            bob.generateKeyPair();

            // Compute shared secrets
            alice.computeSharedSecret(bob.getPublicKey());
            bob.computeSharedSecret(alice.getPublicKey());

            System.out.println("Alice's Shared Secret: " + Base64.getEncoder().encodeToString(alice.getSharedSecret()));
            System.out.println("Bob's Shared Secret: " + Base64.getEncoder().encodeToString(bob.getSharedSecret()));

            if (Arrays.equals(alice.getSharedSecret(), bob.getSharedSecret())) {
                addMessageToChat("Key exchange successful!", false);
            } else {
                addMessageToChat("Key exchange failed!", false);
            }
        } catch (InvalidKeyException ex) {
            addMessageToChat("Key exchange failed: " + ex.getMessage(), false);
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
                    case "Manual DH":
                        if (manualDhAlice != null) {
                            sharedSecret = manualDhAlice.getSharedSecret();
                        }
                        break;
                    case "Manual ECDH":
                        if (alice != null) {
                            sharedSecret = alice.getSharedSecret();
                        }
                        break;
                    default:
                        System.err.println("Algorithm not implemented for encryption.");
                        return;
                }

                if (sharedSecret == null) {
                    System.err.println("Perform key exchange first!");
                    return;
                }

                // Derive AES key from the PRE-COMPUTED shared secret
                SecretKey aesKey = deriveAESKey(sharedSecret);

                // Encrypt the message
                byte[] encryptedMessage = encryptMessage(message, aesKey);

                // Display encrypted message
                String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);
                System.out.println("Encrypted Message: " + encryptedMessageBase64);
                addMessageToChat("Encrypted: " + encryptedMessageBase64, false);

                // Decrypt message (simulate Alice's side)
                String decryptedMessage = new String(decryptMessage(encryptedMessage, aesKey));
                System.out.println("Decrypted Message (Alice received): " + decryptedMessage);
                addMessageToChat("Decrypted (Alice): " + decryptedMessage, false);


                messageInput.clear();
            } catch (Exception e) {
                System.err.println("Failed to send message: " + e.getMessage());
            }
        }
    }

    private SecretKey deriveAESKey(byte[] sharedSecret) throws Exception {
        // Simple derivation of AES key (for demonstration purposes), use something else in practice
        byte[] derivedKeyBytes = Arrays.copyOf(sharedSecret, 16); // 128-bit AES
        return new SecretKeySpec(derivedKeyBytes, "AES");
    }

    private byte[] encryptMessage(String message, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(message.getBytes());
    }

    private byte[] decryptMessage(byte[] encryptedMessage, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(encryptedMessage);
    }
}