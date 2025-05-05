package org.example;

import javafx.animation.Animation;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
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
import javafx.util.Duration;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private final Map<String, ManualDiffieHellman> dhInstances = new ConcurrentHashMap<>();

    private ObservableList<String> chatMessages = FXCollections.observableArrayList();

    private WebClient webClient;
    private String currentUser;
    private String authHeader;

    private Map<String, Object> cryptoInstances = new ConcurrentHashMap<>();
    private Map<String, ObservableList<String>> chatHistories = new ConcurrentHashMap<>();
    private final Map<String, Object> keyExchangeInstances = new ConcurrentHashMap<>();
    private final Map<String, SecretKey> sharedSecrets = new ConcurrentHashMap<>();
    private ListView<String> contactList;
    private TabPane chatTabs;


    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        showLoginDialog(primaryStage);

    }
    private static final Logger log = LoggerFactory.getLogger(MainGUI.class);
    private ExchangeFilterFunction logRequest() {
        return ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
            log.info("Request: {} {}", clientRequest.method(), clientRequest.url());
            clientRequest.headers()
                    .forEach((name, values) ->
                            values.forEach(value -> log.info("{}: {}", name, value)));
            return Mono.just(clientRequest);
        });
    }

    private ExchangeFilterFunction logResponse() {
        return ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
            log.info("Response status code: {}", clientResponse.statusCode());
            clientResponse.headers().asHttpHeaders()
                    .forEach((name, values) ->
                            values.forEach(value -> log.info("{}: {}", name, value)));
            return Mono.just(clientResponse);
        });
    }
    private void initializeNetwork() {
        this.webClient = WebClient.builder()
                .baseUrl("http://localhost:8080")
                .defaultHeaders(headers -> headers.setBasicAuth(currentUser, ""))
                .filter(logRequest())
                .filter(logResponse())
                .build();
    }

    private void showLoginDialog(Stage mainStage) {
        TextInputDialog loginDialog = new TextInputDialog();
        loginDialog.setTitle("Secure Chat Login");
        loginDialog.setHeaderText("Enter your username:");

        loginDialog.showAndWait().ifPresent(username -> {
            this.currentUser = username;
            this.authHeader = "Basic " + Base64.getEncoder()
                    .encodeToString((username + ":").getBytes());

            initializeNetwork();
            initializeUser(username);
            setupMainUI(mainStage);
            startMessagePolling();
        });
    }

    private void initializeUser(String username) {
        Boolean exists = WebClient.create()
                .get()
                .uri("http://localhost:8080/api/users/exists/{username}", username)
                .retrieve()
                .bodyToMono(Boolean.class)
                .block();

        if (exists == null || !exists) {
            WebClient.create()
                    .post()
                    .uri("http://localhost:8080/api/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(new UserRegistrationRequest(username, ""))
                    .retrieve()
                    .bodyToMono(Void.class)
                    .block();
        }
    }

    private void startMessagePolling() {
        Timeline poller = new Timeline(new KeyFrame(Duration.seconds(3), e -> {
            try {
                List<Message> messages = webClient.get()
                        .uri("/api/messages/{username}", currentUser)
                        .retrieve()
                        .bodyToFlux(Message.class)
                        .collectList()
                        .block();

                processIncomingMessages(messages);
            } catch (Exception ex) {
                updateChat("System", "Message poll error: " + ex.getMessage(), false);
            }
        }));
        poller.setCycleCount(Animation.INDEFINITE);
        poller.play();
    }

    private void processIncomingMessages(List<Message> messages) {
        if (messages == null) return;

        messages.forEach(msg -> {
            try {
                // 1) pull out the sender’s username
                String sender = msg.getSenderUsername();

                // 2) look up the shared AES key you derived for that contact
                SecretKey key = sharedSecrets.get(sender);
                if (key == null) {
                    throw new IllegalStateException(
                            "No shared secret for " + sender + "; perform key exchange first");
                }

                // 3) decrypt the Base64‐encoded iv & ciphertext
                String decrypted = decryptMessage(msg, key);

                // 4) update the UI
                updateChat(sender, decrypted, false);
            } catch (Exception e) {
                updateChat("System", "Decryption error: " + e.getMessage(), false);
            }
        });
    }

    private void updateChat(String sender, String message, boolean isOutgoing) {
        Platform.runLater(() ->
                chatList.getItems().add((isOutgoing ? "You: " : sender + ": ") + message)
        );
    }


//    private void checkMessages() {
//        try {
//            List<Message> messages = webClient.get()
//                    .uri("/api/messages/{username}", currentUser)
//                    .header("Authorization", authHeader)
//                    .retrieve()
//                    .onStatus(
//                            status -> status == HttpStatus.UNAUTHORIZED,
//                            response -> Mono.error(new RuntimeException("Unauthorized"))
//                    )
//                    .bodyToFlux(Message.class)
//                    .collectList()
//                    .block();
//
//            if (messages != null) {
//                messages.forEach(msg -> {
//                    String sender = msg.getSender().getUsername();
//                    try {
//                        SecretKey aesKey = sharedSecrets.get(sender);
//                        if (aesKey != null) {
//                            String decrypted = decryptMessage(msg, aesKey);
//                            updateChatHistory(sender, decrypted, false);
//                        }
//                    } catch (Exception e) {
//                        updateChatHistory(sender, "Decryption failed: " + e.getMessage(), false);
//                    }
//                });
//            }
//        } catch (Exception e) {
//            Platform.runLater(() ->
//                    updateChatHistory("System", "Error checking messages: " + e.getMessage(), false));
//        }
//    }



    private void updateChatHistory(String contact, String message, boolean isOutgoing) {
        Platform.runLater(() -> {
            String formatted = (isOutgoing ? "You: " : contact + ": ") + message;
            chatMessages.add(formatted);
            chatList.scrollTo(chatMessages.size() - 1);
        });
    }

    private void setupMainUI(Stage stage) {
        stage.setTitle("Secure Chat - " + currentUser);

        // Contact List
        contactList = new ListView<>(FXCollections.observableArrayList("Alice", "Bob"));
        contactList.getSelectionModel().selectedItemProperty().addListener(
                (obs, old, newContact) -> handleContactSelection(newContact)
        );

        // Chat Area
        chatList = new ListView<>();
        messageInput = new TextField();
        messageInput.setPromptText("Type your message...");

        // Algorithm Selection
        algorithmChoice = new ChoiceBox<>(FXCollections.observableArrayList(
                "Manual ECDH", "Manual DH", "ECDH", "DH"
        ));
        algorithmChoice.setValue("Manual ECDH");

        // Control Buttons
        Button exchangeBtn = new Button("Start Key Exchange");
        exchangeBtn.setOnAction(e -> startKeyExchange());

        Button sendBtn = new Button("Send");
        sendBtn.setOnAction(e -> sendMessage());

        // Layout Configuration
        VBox chatContainer = new VBox(10,
                new HBox(10, new Label("Algorithm:"), algorithmChoice, exchangeBtn),
                chatList,
                new HBox(10, messageInput, sendBtn)
        );

        BorderPane root = new BorderPane();
        root.setLeft(new VBox(new Label("Contacts"), contactList));
        root.setCenter(chatContainer);

        stage.setScene(new Scene(root, 800, 600));
        stage.show();
    }

    private void handleContactSelection(String contact) {
        if (contact != null) {
            chatList.getItems().clear();
            messageInput.setDisable(false);
        }
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
        contactList = new ListView<>(); // Initialize contactList
        contactList.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);

        // Add sample contacts (replace with real data later)
        ObservableList<String> contacts = FXCollections.observableArrayList(
                "Alice", "Bob"
        );
        contactList.setItems(contacts);

        contactsPanel.getChildren().addAll(
                new Label("Contacts"),
                contactList
        );
        return contactsPanel;
    }

//    private VBox createChatContainer() {
//        VBox chatContainer = new VBox();
//        chatContainer.getStyleClass().add("chat-container");
//
//        // Chat header
//        HBox chatHeader = new HBox(10);
//        chatHeader.getStyleClass().add("chat-header");
//        Label chatTitle = new Label("Alice");
//        chatTitle.getStyleClass().add("chat-title");
//
//        HBox controls = new HBox(10);
//        algorithmChoice = new ChoiceBox<>();
//        algorithmChoice.getItems().addAll("Diffie-Hellman", "ECDH", "Manual DH", "Manual ECDH");
//        algorithmChoice.setValue("Manual ECDH");
//        algorithmChoice.getStyleClass().add("algorithm-choice");
//
//        Button startExchangeBtn = new Button("Start Key Exchange");
//        startExchangeBtn.getStyleClass().add("exchange-btn");
//        startExchangeBtn.setOnAction(e -> startKeyExchange());
//
//        controls.getChildren().addAll(
//                new Label("Algorithm:"), algorithmChoice, startExchangeBtn
//        );
//
//        chatHeader.getChildren().addAll(chatTitle, controls);
//
//        // chat
//        chatList = new ListView<>();
//        chatList.getStyleClass().add("chat-list");
//        VBox.setVgrow(chatList, Priority.ALWAYS); // proper sizing
//        chatList.setCellFactory(param -> new MessageCell());
//
//        // Message input area
//        HBox messageBox = new HBox(10);
//        messageBox.getStyleClass().add("message-box");
//
//
//        messageInput = new TextField();
//        messageInput.setPromptText("Type your message...");
//        messageInput.getStyleClass().add("message-input");
//
//        Button sendBtn = new Button("Send");
//        sendBtn.getStyleClass().add("send-btn");
//        sendBtn.setOnAction(e -> {
//            String message = messageInput.getText();
//            if (!message.isEmpty()) {
//                String contact = getSelectedContact();
//                sendMessage(contact, message);
//                messageInput.clear();
//            }
//        });
////
////        sendBtn.setOnAction(e -> {
////            String message = messageInput.getText();
////            if (message.isEmpty()) return;
////
////            String contact = getSelectedContact();
////            if (chatTabs != null && !chatTabs.getTabs().isEmpty()) {
////                sendMessage(contact, message);
////                messageInput.clear();
////            } else {
////                updateChatHistory("System", "No active chat selected", false);
////            }
////        });
//
//        messageBox.getChildren().addAll(messageInput, sendBtn);
//
//        chatContainer.getChildren().addAll(chatHeader, chatList, messageBox);
//        return chatContainer;
//    }


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



//    private void startKeyExchange() {
//        String algorithm = algorithmChoice.getValue();
//        String contact = getSelectedContact();
//
//        if (contact == null || contact.isEmpty()) {
//            updateChatHistory("System", "Select a contact first!", false);
//            return;
//        }
//
//        new Thread(() -> {
//            try {
//                switch (algorithm) {
//                    case "Diffie-Hellman":
//                        DiffieHellmanExample dh = new DiffieHellmanExample();
//                        PublicKey partnerKey = getPartnerPublicKey(contact, "DH");
//                        dh.performKeyExchange(partnerKey);
//                        break;
//
//                    case "ECDH":
//                        ECDiffieHellmanExample ecdh = new ECDiffieHellmanExample();
//                        PublicKey ecPartnerKey = getPartnerPublicKey(contact, "EC");
//                        ecdh.performKeyExchange(ecPartnerKey);
//                        break;
//
//                    case "Manual DH":
//                        runManualDH(contact);
//                        break;
//
//                    case "Manual ECDH":
//                        runManualECDH(contact);
//                        break;
//                }
//                Platform.runLater(() ->
//                        updateChatHistory(contact, algorithm + " key exchange completed!", false));
//            } catch (Exception e) {
//                Platform.runLater(() ->
//                        updateChatHistory(contact, "Key exchange failed: " + e.getMessage(), false));
//            }
//        }).start();
//    }

    private void startKeyExchange() {
        String contact = getSelectedContact();
        if (contact == null) {
            updateChat("System", "Select a contact first!", false);
            return;
        }

        String algorithm = algorithmChoice.getValue();
        Executors.newSingleThreadExecutor().execute(() -> {
            try {
                switch (algorithm) {
                    case "Manual DH":
                        performManualDh(contact);
                        break;
                    // TODO: mirror this pattern for “DH”, “Manual ECDH”, “ECDH”
                    default:
                        throw new IllegalStateException("Unsupported algorithm: " + algorithm);
                }
                Platform.runLater(() ->
                        updateChat("System", "Key exchange with " + contact + " successful!", false)
                );
            } catch (Exception e) {
                Platform.runLater(() ->
                        updateChat("System", "Key exchange failed: " + e.getMessage(), false)
                );
            }
        });
    }
    private void performManualECDH(String contact) throws Exception {
        ManualECDiffieHellman ecdh = new ManualECDiffieHellman();
        ecdh.generateKeyPair();

        // Exchange public keys through server
        webClient.put()
                .uri("/api/users/{username}/public-key", currentUser)
                .bodyValue(ecdh.getPublicKey())
                .retrieve()
                .toBodilessEntity()
                .block();

        // Get partner's public key
        String partnerKey = webClient.get()
                .uri("/api/users/{username}/public-key", contact)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        // Parse and compute shared secret
        ManualECDiffieHellman.ECPoint partnerPoint = parseECPoint(partnerKey);
        ecdh.computeSharedSecret(partnerPoint);

        // Store derived AES key
        byte[] rawSecret = ecdh.getSharedSecret();
        SecretKey aesKey = deriveAESKey(rawSecret);
        sharedSecrets.put(contact, aesKey);
    }
    private ManualECDiffieHellman.ECPoint parseECPoint(String keyStr) throws NumberFormatException {
        String[] parts = keyStr.split(",");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid public key format");
        }
        return new ManualECDiffieHellman.ECPoint(
                new BigInteger(parts[0]),
                new BigInteger(parts[1])
        );
    }


    private void performManualDh(String contact) throws Exception {
        // 1) If this is the first click for this contact, generate + upload your public key
        ManualDiffieHellman dh = dhInstances.computeIfAbsent(contact, c -> {
            ManualDiffieHellman instance = new ManualDiffieHellman();
            instance.initialize();  // gen private & public

            // upload my public key
            webClient.put()
                    .uri(uriBuilder -> uriBuilder
                            .path("/api/users/{u}/public-key").build(currentUser))
                    .bodyValue(instance.getPublicKey())
                    .retrieve().toBodilessEntity().block();

            return instance;
        });

        // 2) Poll for partner’s public key (the other side’s PUT)
        String partnerPub = null;
        final int MAX_ATTEMPTS = 20;
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            Thread.sleep(300);
            partnerPub = webClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/api/users/{u}/public-key").build(contact))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
            if (partnerPub != null && !partnerPub.isBlank()) {
                break;
            }
        }
        if (partnerPub == null || partnerPub.isBlank()) {
            throw new RuntimeException("Timed out waiting for " + contact + " to publish their public key");
        }

        // 3) Compute the shared secret exactly once
        dh.computeSharedSecret(new BigInteger(partnerPub));
        byte[] raw = dh.getSharedSecret();
        SecretKey aesKey = deriveAESKey(raw);
        sharedSecrets.put(contact, aesKey);

        // 4) (Optional) remove the instance if not planning to re-use it:
        // dhInstances.remove(contact);
    }



    private void performDhWithLibrary(String contact) throws Exception {
        DiffieHellmanExample dhExample = new DiffieHellmanExample();
        String myPubEncoded = dhExample.getPublicKey();  // base64-encoded X.509

        // send yours
        webClient.put()
                .uri("/api/users/{username}/public-key", currentUser)
                .bodyValue(myPubEncoded)
                .retrieve().toBodilessEntity().block();

        // fetch theirs
        String partnerPubB64 = webClient.get()
                .uri("/api/users/{username}/public-key", contact)
                .retrieve().bodyToMono(String.class).block();

        // compute shared secret
        PublicKey partnerKey = KeyFactory.getInstance("DH")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(partnerPubB64)));
        dhExample.performKeyExchange(partnerKey);
        byte[] rawSecret = dhExample.getSharedSecret();

        SecretKey aesKey = deriveAESKey(rawSecret);
        sharedSecrets.put(contact, aesKey);
    }


    private void performEcdhWithLibrary(String contact) throws Exception {
        ECDiffieHellmanExample ecExample = new ECDiffieHellmanExample();
        String myPub = ecExample.getPublicKey();

        webClient.put()
                .uri("/api/users/{username}/public-key", currentUser)
                .bodyValue(myPub).retrieve().toBodilessEntity().block();

        String partnerPub = webClient.get()
                .uri("/api/users/{username}/public-key", contact)
                .retrieve().bodyToMono(String.class).block();

        PublicKey partnerKey = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(partnerPub)));
        ecExample.performKeyExchange(partnerKey);

        SecretKey aesKey = deriveAESKey(ecExample.getSharedSecret());
        sharedSecrets.put(contact, aesKey);
    }


    private PublicKey getPartnerPublicKey(String contact, String algorithm) throws Exception {
        String keyStr = webClient.get()
                .uri("/api/users/{username}/public-key", contact)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        return KeyFactory.getInstance(algorithm)
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(keyStr)));
    }

    private void showAlert(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle(title);
            alert.setContentText(message);
            alert.show();
        });
    }

    private void runManualDH(String contact) {
        try {
            // Initialize current user's DH parameters
            ManualDiffieHellman manualDH = new ManualDiffieHellman();
            manualDH.initialize();

            // Send our public key to server
            webClient.put()
                    .uri("/api/users/{username}/public-key", currentUser)
                    .bodyValue(manualDH.getPublicKey())
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            // Get partner's public key from server
            String partnerKeyStr = webClient.get()
                    .uri("/api/users/{username}/public-key", contact)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            // Convert partner's public key string to BigInteger
            BigInteger partnerPublicKey = new BigInteger(partnerKeyStr);

            // Compute shared secret
            manualDH.computeSharedSecret(partnerPublicKey);

            // Derive AES key and store it
            SecretKey aesKey = deriveAESKey(manualDH.getSharedSecret());
            sharedSecrets.put(contact, aesKey);

            Platform.runLater(() ->
                    updateChatHistory(contact, "Manual DH key exchange successful!", false));

        } catch (NumberFormatException e) {
            Platform.runLater(() ->
                    updateChatHistory(contact, "Invalid public key format from partner", false));
        } catch (Exception e) {
            Platform.runLater(() ->
                    updateChatHistory(contact, "Manual DH failed: " + e.getMessage(), false));
        }
    }

    private void runManualECDH(String contact) {
        try {
            ManualECDiffieHellman alice = new ManualECDiffieHellman();
            alice.generateKeyPair();

            // Get Bob's public key from server
            String bobKeyStr = webClient.get()
                    .uri("/api/users/{username}/public-key", contact)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            // Parse Bob's public key
            String[] coords = bobKeyStr.split(",");
            ManualECDiffieHellman.ECPoint bobPublicKey =
                    new ManualECDiffieHellman.ECPoint(
                            new BigInteger(coords[0]),
                            new BigInteger(coords[1])
                    );

            // Compute shared secret
            alice.computeSharedSecret(bobPublicKey);

            // Store secret
            sharedSecrets.put(contact, deriveAESKey(alice.getSharedSecret()));

            updateChatHistory(contact, "Manual ECDH Successful!", false);
        } catch (Exception e) {
            updateChatHistory(contact, "Manual ECDH Failed: " + e.getMessage(), false);
        }
    }







    private static final int GCM_IV_LENGTH = 12; // 96 bits for GCM
    private static final int GCM_TAG_LENGTH = 16 * 8; // 128-bit authentication tag

    private byte[] encryptMessage(String plaintext, SecretKey key) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }

    private String decryptMessage(Message encryptedMessage, SecretKey key) throws GeneralSecurityException {
        byte[] iv = Base64.getDecoder().decode(encryptedMessage.getIv());
        byte[] ciphertext = Base64.getDecoder().decode(encryptedMessage.getCiphertext());

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }


    private String getSelectedContact() {
        return contactList.getSelectionModel().getSelectedItem();
    }

    private void performKeyExchange(String contact, String algorithm) {
        keyExchangeInstances.put(contact, algorithm);

        new Thread(() -> {
            try {
                Object cryptoInstance;
                String publicKeyToSend;

                switch (algorithm) {
                    case "Diffie-Hellman":
                        DiffieHellmanExample dh = new DiffieHellmanExample();
                        cryptoInstance = dh;
                        publicKeyToSend = dh.getPublicKey();
                        break;

                    case "ECDH":
                        ECDiffieHellmanExample ecdh = new ECDiffieHellmanExample();
                        cryptoInstance = ecdh;
                        publicKeyToSend = ecdh.getPublicKey();
                        break;

                    case "Manual DH":
                        ManualDiffieHellman manualDH = new ManualDiffieHellman();
                        manualDH.initialize();
                        cryptoInstance = manualDH;
                        publicKeyToSend = manualDH.getPublicKey();
                        break;

                    case "Manual ECDH":
                        ManualECDiffieHellman manualECDH = new ManualECDiffieHellman();
                        manualECDH.generateKeyPair();
                        cryptoInstance = manualECDH;
                        publicKeyToSend = manualECDH.getPublicKey();
                        break;

                    default: throw new IllegalArgumentException("Invalid algorithm");
                }

                // Exchange public keys through server
                webClient.put()
                        .uri("/api/users/{username}/public-key", currentUser)
                        .bodyValue(publicKeyToSend)
                        .retrieve()
                        .toBodilessEntity()
                        .block();

                // Get partner's public key
                String partnerKey = webClient.get()
                        .uri("/api/users/{username}/public-key", contact)
                        .retrieve()
                        .bodyToMono(String.class)
                        .block();

                // Compute shared secret
                byte[] rawSecret = computeSharedSecret(algorithm, cryptoInstance, partnerKey);
                SecretKey aesKey = deriveAESKey(rawSecret);
                sharedSecrets.put(contact, aesKey);

                Platform.runLater(() ->
                        updateChatHistory(contact, algorithm + " key exchange successful!", false));

            } catch (Exception e) {
                Platform.runLater(() ->
                        updateChatHistory(contact, "Key exchange failed: " + e.getMessage(), false));
            }
        }).start();
    }


    private byte[] computeSharedSecret(String algorithm, Object instance, String partnerKey)
            throws Exception {
        switch (algorithm) {
            case "Diffie-Hellman":
                DiffieHellmanExample dh = (DiffieHellmanExample) instance;
                PublicKey dhPublicKey = KeyFactory.getInstance("DH")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(partnerKey)));
                dh.performKeyExchange(dhPublicKey);
                return dh.getSharedSecret();

            case "ECDH":
                ECDiffieHellmanExample ecdh = (ECDiffieHellmanExample) instance;
                PublicKey ecPublicKey = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(partnerKey)));
                ecdh.performKeyExchange(ecPublicKey);
                return ecdh.getSharedSecret();

            case "Manual DH":
                ManualDiffieHellman manualDH = (ManualDiffieHellman) instance;
                BigInteger dhPublic = new BigInteger(partnerKey);
                manualDH.computeSharedSecret(dhPublic);
                return manualDH.getSharedSecret();

            case "Manual ECDH":
                ManualECDiffieHellman manualECDH = (ManualECDiffieHellman) instance;
                String[] coords = partnerKey.split(",");
                ManualECDiffieHellman.ECPoint point = new ManualECDiffieHellman.ECPoint(
                        new BigInteger(coords[0]), new BigInteger(coords[1]));
                manualECDH.computeSharedSecret(point);
                return manualECDH.getSharedSecret();

            default: throw new IllegalArgumentException("Invalid algorithm");
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

    private void sendMessage() {
        String message = messageInput.getText();
        String contact = getSelectedContact();

        if (message.isEmpty() || contact == null) return;

        Executors.newSingleThreadExecutor().execute(() -> {
            try {
                SecretKey key = sharedSecrets.get(contact);
                if (key == null) throw new Exception("Perform key exchange first");

                byte[] encrypted = encryptMessage(message, key);
                EncryptedMessage msg = EncryptedMessage.fromBytes(encrypted);

                webClient.post()
                        .uri("/api/messages")
                        .bodyValue(new MessageRequest(
                                currentUser, contact, msg.ciphertext(), msg.iv()))
                        .retrieve()
                        .toBodilessEntity()
                        .block();

                Platform.runLater(() -> updateChat("You", message, true));
            } catch (Exception e) {
                Platform.runLater(() -> updateChat(
                        "System", "Send failed: " + e.getMessage(), false));
            }
        });
    }



    private byte[] completeKeyExchange(String algorithm, Object cryptoInstance, String partnerKey)
            throws Exception {
        switch (algorithm) {
            case "Diffie-Hellman":
                KeyAgreement dhAgreement = (KeyAgreement) cryptoInstance;
                PublicKey dhPublicKey = KeyFactory.getInstance("DH")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(partnerKey)));
                dhAgreement.doPhase(dhPublicKey, true);
                return dhAgreement.generateSecret();

            case "ECDH":
                KeyAgreement ecAgreement = (KeyAgreement) cryptoInstance;
                PublicKey ecPublicKey = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(partnerKey)));
                ecAgreement.doPhase(ecPublicKey, true);
                return ecAgreement.generateSecret();

            case "Manual DH":
                ManualDiffieHellman manualDH = (ManualDiffieHellman) cryptoInstance;
                BigInteger partnerPublicKey = new BigInteger(partnerKey);
                return manualDH.computeSharedSecret(
                        manualDH.getPrivateKey(),
                        partnerPublicKey
                );

            case "Manual ECDH":
                ManualECDiffieHellman manualECDH = (ManualECDiffieHellman) cryptoInstance;
                String[] coordinates = partnerKey.split(",");
                ManualECDiffieHellman.ECPoint partnerPoint =
                        new ManualECDiffieHellman.ECPoint(
                                new BigInteger(coordinates[0]),
                                new BigInteger(coordinates[1])
                        );
                manualECDH.computeSharedSecret(partnerPoint);
                return manualECDH.getSharedSecret();

            default:
                throw new IllegalArgumentException("Unsupported algorithm");
        }
    }

}