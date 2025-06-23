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
import org.springframework.http.MediaType;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ch.qos.logback.core.encoder.ByteArrayUtil.hexStringToByteArray;

public class MainGUI extends Application {


    private ListView<String> chatList;
    private TextField messageInput;
    private ChoiceBox<String> algorithmChoice;
    private final Map<String, ManualDiffieHellman> dhInstances = new ConcurrentHashMap<>();

    private ObservableList<String> chatMessages = FXCollections.observableArrayList();

    private WebClient webClient;
    private String currentUser;
    private String authHeader;


    private final Map<String, SecretKey> sharedSecrets = new ConcurrentHashMap<>();
    private ListView<String> contactList;
    // Manual DH
    private final Map<String, ManualDiffieHellman> manualDhInstances = new ConcurrentHashMap<>();
    // Library DH
    private final Map<String, KeyPair> dhLibKeyPairs     = new ConcurrentHashMap<>();
    // Manual ECDH
    private final Map<String, ManualECDiffieHellman> manualEcdhInstances = new ConcurrentHashMap<>();
    // Library ECDH
    private final Map<String, KeyPair> ecdhLibKeyPairs   = new ConcurrentHashMap<>();

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
                // 1) pull out sender username
                String sender = msg.getSenderUsername();

                // 2) look up the shared AES key you derived for contact
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



    private void setupMainUI(Stage stage) {
        stage.setTitle("Secure Chat - " + currentUser);

        // TODO: non-fixed kontakty
        // Contact List
        contactList = new ListView<>(FXCollections.observableArrayList("Alice", "Bob", "Eve"));
        contactList.getSelectionModel().selectedItemProperty().addListener(
                (obs, old, newContact) -> handleContactSelection(newContact)
        );

        // chat area
        chatList = new ListView<>();
        messageInput = new TextField();
        messageInput.setPromptText("Type your message...");

        // algorithm selection
        algorithmChoice = new ChoiceBox<>(FXCollections.observableArrayList(
                "Manual ECDH", "Manual DH", "ECDH", "DH"
        ));
        algorithmChoice.setValue("Manual ECDH");

        // buttons
        Button exchangeBtn = new Button("Start Key Exchange");
        exchangeBtn.setOnAction(e -> startKeyExchange());

        Button sendBtn = new Button("Send");
        sendBtn.setOnAction(e -> sendMessage());

        // layout config
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




    private void startKeyExchange() {
        String contact = getSelectedContact();
        if (contact == null) {
            updateChat("System", "Select a contact first!", false);
            return;
        }
        String alg = algorithmChoice.getValue();

        Executors.newSingleThreadExecutor().execute(() -> {
            try {
                switch (alg) {
                    case "Manual DH":
                        performManualDh(contact); break;
                    case "DH":
                        performDhWithLibrary(contact); break;
                    case "Manual ECDH":
                        performManualECDH(contact); break;
                    case "ECDH":
                        performEcdhWithLibrary(contact); break;
                    default:
                        throw new IllegalStateException("Unknown algorithm: " + alg);
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
        ManualECDiffieHellman ecdh = manualEcdhInstances.computeIfAbsent(contact, c -> {
            ManualECDiffieHellman inst = new ManualECDiffieHellman();
            try {
                inst.generateKeyPair();
                // Publish public key
                webClient.put()
                        .uri("/api/users/{u}/public-key", currentUser)
                        .contentType(MediaType.TEXT_PLAIN)          // ← here
                        .bodyValue(inst.getPublicKey())
                        .retrieve().toBodilessEntity().block();
                return inst;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        // Fetch partner public key
        String pk = pollForPublicKey(contact);
        // Expect hex uncompressed: 04||X||Y
        byte[] raw = hexStringToByteArray(pk);
        if (raw.length != 65 || raw[0] != 0x04) throw new InvalidKeyException("Invalid public key format");
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(raw, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(raw, 33, 65));
        // Compute shared secret
        ecdh.computeSharedSecret(new ManualECDiffieHellman.ECPointAffine(x, y));
        byte[] secret = ecdh.getSharedSecret();
        SecretKey aes = new SecretKeySpec(secret, 0, 16, "AES");
        sharedSecrets.put(contact, aes);
    }
    private String pollForPublicKey(String contact) throws InterruptedException {
        for (int i = 0; i < 20; i++) {
            String val = webClient.get()
                    .uri("/api/users/{u}/public-key", contact)
                    .retrieve().bodyToMono(String.class).block();
            if (val != null && !val.isBlank()) return val;
            Thread.sleep(300);
        }
        throw new RuntimeException("Timed out waiting for " + contact + " public key");
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
                    .contentType(MediaType.TEXT_PLAIN)          // ← here
                    .bodyValue(instance.getPublicKey().toString())
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


    }



    private void performDhWithLibrary(String contact) throws Exception {
        // 1) generate or reuse DH keypair
        KeyPair kp = dhLibKeyPairs.computeIfAbsent(contact, c -> {
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance("DH");
                g.initialize(2048);
                KeyPair pair = g.generateKeyPair();
                // upload public key
                String pubB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
                webClient.put()
                        .uri(b -> b.path("/api/users/{u}/public-key").build(currentUser))
                        .bodyValue(pubB64)
                        .retrieve().toBodilessEntity().block();
                return pair;
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });

        // 2) poll partner
        String partnerB64 = pollForKey(contact);

        // 3) reconstruct their PublicKey
        byte[] decoded = Base64.getDecoder().decode(partnerB64);
        PublicKey partnerKey = KeyFactory.getInstance("DH")
                .generatePublic(new X509EncodedKeySpec(decoded));

        // 4) key agreement
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(kp.getPrivate());
        ka.doPhase(partnerKey, true);
        byte[] raw = ka.generateSecret();
        sharedSecrets.put(contact, deriveAESKey(raw));
    }


    private void performEcdhWithLibrary(String contact) throws Exception {
        // 1) generate or reuse EC keypair
        KeyPair kp = ecdhLibKeyPairs.computeIfAbsent(contact, c -> {
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair pair = g.generateKeyPair();
                String pubB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
                webClient.put()
                        .uri(b -> b.path("/api/users/{u}/public-key").build(currentUser))
                        .bodyValue(pubB64)
                        .retrieve().toBodilessEntity().block();
                return pair;
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });

        // 2) poll partner
        String partnerB64 = pollForKey(contact);

        // 3) reconstruct and agree
        byte[] decoded = Base64.getDecoder().decode(partnerB64);
        PublicKey partnerKey = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(decoded));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(partnerKey, true);
        byte[] raw = ka.generateSecret();
        sharedSecrets.put(contact, deriveAESKey(raw));
    }

    /** Polls /api/users/{contact}/public-key until non-empty or times out */
    private String pollForKey(String contact) {
        String keyStr;
        final int MAX = 20;
        for (int i = 0; i < MAX; i++) {
            keyStr = webClient.get()
                    .uri(b -> b.path("/api/users/{u}/public-key").build(contact))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
            if (keyStr != null && !keyStr.isBlank()) {
                return keyStr;
            }
            try { Thread.sleep(300); } catch (InterruptedException ignored) {}
        }
        throw new RuntimeException("Timed out waiting for " + contact + " to publish their public key");
    }




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




}