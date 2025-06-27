package org.example;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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

    private final ObjectMapper objectMapper = new ObjectMapper();

    // negocjacja
    private Map<String, Boolean> awaitingAlgorithmConfirmation = new ConcurrentHashMap<>();
    private Map<String, String> contactAlgorithm = new ConcurrentHashMap<>();

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

//    private void processIncomingMessages(List<Message> messages) {
//        if (messages == null) return;
//
//        messages.forEach(msg -> {
//            try {
//                // 1) pull out sender username
//                String sender = msg.getSenderUsername();
//
//                // 2) look up the shared AES key you derived for contact
//                SecretKey key = sharedSecrets.get(sender);
//                if (key == null) {
//                    throw new IllegalStateException(
//                            "No shared secret for " + sender + "; perform key exchange first");
//                }
//
//                // 3) decrypt the Base64‐encoded iv & ciphertext
//                String decrypted = decryptMessage(msg, key);
//
//                // 4) update the UI
//                updateChat(sender, decrypted, false);
//            } catch (Exception e) {
//                updateChat("System", "Decryption error: " + e.getMessage(), false);
//            }
//        });
//    }

    private void handleControlPayload(String sender, String payloadJson) {
        try {
            JsonNode node = objectMapper.readTree(payloadJson);
            String action = node.path("action").asText(null);
            if ("KEY_EXCHANGE_PROPOSAL".equals(action)) {
                String newAlg = node.get("algorithm").asText();
                // Pytamy użytkownika przez dialog
                Platform.runLater(() -> promptAlgorithmChange(sender, newAlg));
            } else if ("KEY_EXCHANGE_RESPONSE".equals(action)) {
                String alg = node.get("algorithm").asText();
                boolean accepted = node.get("accepted").asBoolean();
                handleKeyExchangeResponse(sender, alg, accepted);
            } else {
                updateChat("System", "Nieznana akcja kontrolna od " + sender + ": " + action, false);
            }
        } catch (Exception e) {
            updateChat("System", "Błąd parsowania control payload: " + e.getMessage(), false);
        }
    }

    private void promptAlgorithmChange(String sender, String newAlg) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Propozycja wymiany klucza");
        alert.setHeaderText(sender + " proponuje wymianę klucza algorytmem: " + newAlg);
        alert.setContentText("Czy akceptujesz?");
        alert.showAndWait().ifPresent(response -> {
            if (response == ButtonType.OK) {
                // 1) Wyślij potwierdzenie
                sendKeyExchangeConfirmation(sender, newAlg, true);

                cleanupKeyExchangeState(sender);

                // 2) Ustaw stan lokalny
                contactAlgorithm.put(sender, newAlg);
                sharedSecrets.remove(sender);
                // 3) Usuń stary public key po stronie serwera
                webClient.delete().uri("/api/users/{u}/public-key", currentUser)
                        .retrieve().toBodilessEntity().block();
                // 4) Synchronizuj ChoiceBox
                Platform.runLater(() -> algorithmChoice.setValue(newAlg));
                cleanupKeyExchangeState(sender);

                // 5) Natychmiastowy handshake B→A
                startKeyExchangeWithAlgorithm(sender, newAlg);
                updateChat("System", "Rozpoczęto wymianę klucza algorytmem " + newAlg, false);
            } else {
                sendKeyExchangeConfirmation(sender, newAlg, false);
                updateChat("System", "Odrzucono wymianę klucza algorytmem " + newAlg, false);
            }
        });
    }

    private void cleanupKeyExchangeState(String contact) {
        // Clear shared secrets
        sharedSecrets.remove(contact);

        // Clear all key exchange instances
        manualDhInstances.remove(contact);
        dhLibKeyPairs.remove(contact);
        manualEcdhInstances.remove(contact);
        ecdhLibKeyPairs.remove(contact);

        // Clear pending states
        awaitingAlgorithmConfirmation.remove(contact);

        // Remove public key from server with retries
        int attempts = 0;
        while (attempts < 3) {
            try {
                Boolean deleted = webClient.delete()
                        .uri("/api/users/{u}/public-key", currentUser)
                        .retrieve()
                        .bodyToMono(Boolean.class)
                        .block(java.time.Duration.ofSeconds(2));  // Fixed

                if (Boolean.TRUE.equals(deleted)) break;
            } catch (Exception e) {
                log.warn("Key delete attempt {} failed: {}", attempts + 1, e.getMessage());
            }
            attempts++;
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        }
    }

    private void handleKeyExchangeResponse(String sender, String alg, boolean accepted) {
        Boolean awaiting = awaitingAlgorithmConfirmation.get(sender);
        if (awaiting != null && awaiting) {
            if (accepted) {
                // Ustaw nowy algorytm w stanie lokalnym
                contactAlgorithm.put(sender, alg);
                sharedSecrets.remove(sender);
                cleanupKeyExchangeState(sender);
                // Usuń stary public key
                webClient.delete().uri("/api/users/{u}/public-key", currentUser)
                        .retrieve().toBodilessEntity().block();
                // Synchronizuj ChoiceBox
                Platform.runLater(() -> algorithmChoice.setValue(alg));
                // Handshake A→B
                startKeyExchangeWithAlgorithm(sender, alg);
                updateChat("System", "Partner zaakceptował. Rozpoczynam wymianę klucza algorytmem " + alg, false);
            } else {
                updateChat("System", "Partner odrzucił zmianę algorytmu na " + alg, false);
            }
            awaitingAlgorithmConfirmation.remove(sender);
        } else {
            updateChat("System", "Otrzymano nieoczekiwane potwierdzenie od " + sender, false);
        }
    }


    private void sendKeyExchangeConfirmation(String contact, String algorithm, boolean accepted) {
        try {
            ObjectNode node = objectMapper.createObjectNode();
            node.put("action", "KEY_EXCHANGE_RESPONSE");
            node.put("algorithm", algorithm);
            node.put("accepted", accepted);
            String json = objectMapper.writeValueAsString(node);

            String ciphertext, iv;
            SecretKey key = sharedSecrets.get(contact);
            if (key != null) {
                byte[] encrypted = encryptMessage(json, key);
                EncryptedMessage em = EncryptedMessage.fromBytes(encrypted);
                ciphertext = em.ciphertext();
                iv = em.iv();
            } else {
                ciphertext = json;
                iv = "";
            }
            MessageRequest req = new MessageRequest(currentUser, contact, "CTRL", ciphertext, iv);
            webClient.post().uri("/api/messages").bodyValue(req).retrieve().toBodilessEntity().block();
        } catch (Exception e) {
            Platform.runLater(() ->
                    updateChat("System", "Błąd wysłania potwierdzenia: " + e.getMessage(), false));
        }
    }














    private void updateChat(String sender, String message, boolean isOutgoing) {
        System.out.println("\n\n\n\n\n\nasdfasddsa");
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
        exchangeBtn.setOnAction(
                e -> startKeyExchange()
        );

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
            // Reset UI state
            chatList.getItems().clear();

            // Reset to default algorithm for this contact
            algorithmChoice.setValue("Manual ECDH");

            // Clear any partial key exchange state
            cleanupKeyExchangeState(contact);

            // Enable messaging
            messageInput.setDisable(false);
        }
    }


    private void sendTextMessage(String contact, String plaintext) {
        try {
            SecretKey key = sharedSecrets.get(contact);
            String type = "TEXT";
            String ciphertextB64;
            String ivB64;
            if (key != null) {
                byte[] encrypted = encryptMessage(plaintext, key);
                EncryptedMessage msg = EncryptedMessage.fromBytes(encrypted);
                ciphertextB64 = msg.ciphertext();
                ivB64 = msg.iv();
            } else {
                // jeśli brak klucza, ewentualnie nie pozwól wysłać plaintext, albo wyślij jawnie:
                ciphertextB64 = plaintext; // lub zablokuj
                ivB64 = "";
            }
            MessageRequest req = new MessageRequest(currentUser, contact, type, ciphertextB64, ivB64);
            webClient.post()
                    .uri("/api/messages")
                    .bodyValue(req)
                    .retrieve().toBodilessEntity().block();
            updateChat("You", plaintext, true);
        } catch (Exception e) {
            updateChat("System", "Send failed: " + e.getMessage(), false);
        }
    }

    private void processIncomingMessages(List<Message> messages) {
        if (messages == null) return;
        for (Message msg : messages) {
            String sender = msg.getSenderUsername();
            String type = msg.getMessageType();
            if ("TEXT".equals(type)) {
                String display;
                try {
                    if (msg.getIv() != null && !msg.getIv().isBlank()) {
                        display = decryptMessage(msg, sharedSecrets.get(sender));
                    } else {
                        display = msg.getCiphertext(); // plaintext?
                    }
                } catch (Exception e) {
                    display = "[Decrypt error: " + e.getMessage() + "]";
                }
                updateChat(sender, display, false);
            }
            else if ("CTRL".equals(type)) {
                String payload;
                try {
                    if (msg.getIv() != null && !msg.getIv().isBlank()) {
                        payload = decryptMessage(msg, sharedSecrets.get(sender));
                    } else {
                        payload = msg.getCiphertext();
                    }
                    handleControlPayload(sender, payload);
                } catch (Exception e) {
                    updateChat("System", "Control msg error: " + e.getMessage(), false);
                }

            } else {
                updateChat("System", "Unknown message type from " + sender, false);
            }
        }
    }

    private void startKeyExchange() {
        String contact = getSelectedContact();
        if (contact == null) {
            updateChat("System", "Select a contact first!", false);
            return;
        }
        String chosenAlg = algorithmChoice.getValue();
        // Wyślij propozycję
        sendKeyExchangeProposal(contact, chosenAlg);
        awaitingAlgorithmConfirmation.put(contact, true);
        updateChat("System", "Propozycja wymiany klucza (algorytm: "
                + chosenAlg + ") wysłana do " + contact, false);
    }

    private void sendKeyExchangeProposal(String contact, String newAlg) {
        try {
            ObjectNode node = objectMapper.createObjectNode();
            node.put("action", "KEY_EXCHANGE_PROPOSAL");
            node.put("algorithm", newAlg);
            String json = objectMapper.writeValueAsString(node);

            String ciphertext, iv;
            SecretKey key = sharedSecrets.get(contact);
            if (key != null) {
                byte[] encrypted = encryptMessage(json, key);
                EncryptedMessage em = EncryptedMessage.fromBytes(encrypted);
                ciphertext = em.ciphertext();
                iv = em.iv();
            } else {
                ciphertext = json;
                iv = "";
            }
            MessageRequest req = new MessageRequest(currentUser, contact, "CTRL", ciphertext, iv);
            webClient.post().uri("/api/messages").bodyValue(req).retrieve().toBodilessEntity().block();
        } catch (Exception e) {
            Platform.runLater(() ->
                    updateChat("System", "Błąd wysłania propozycji wymiany klucza: " + e.getMessage(), false));
        }
    }


    private void startKeyExchangeWithAlgorithm(String contact, String alg) {
        // Ensure fresh state before starting
        cleanupKeyExchangeState(contact);

        Executors.newSingleThreadExecutor().execute(() -> {
            try {
                // Add delay to ensure server processes cleanup
                Thread.sleep(300);

                switch (alg) {
                    case "Manual DH":
                        performManualDh(contact);
                        break;
                    case "DH":
                        performDhWithLibrary(contact);
                        break;
                    case "Manual ECDH":
                        performManualECDH(contact);
                        break;
                    case "ECDH":
                        performEcdhWithLibrary(contact);
                        break;
                    default:
                        throw new IllegalStateException("Unknown algorithm: " + alg);
                }
                Platform.runLater(() ->
                        updateChat("System", "Key exchange (" + alg + ") with " + contact + " successful!", false));
            } catch (Exception e) {
                Platform.runLater(() ->
                        updateChat("System", "Key exchange (" + alg + ") failed: " + e.getMessage(), false));
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
                return g.generateKeyPair();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });

        // 2) upload public key
        String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        webClient.put()
                .uri(b -> b.path("/api/users/{u}/public-key").build(currentUser))
                .bodyValue(pubB64)
                .retrieve().toBodilessEntity().block();

        // 3) poll partner with format validation
        String partnerB64 = null;
        for (int i = 0; i < 30; i++) {  // Increased timeout to 9 seconds
            String candidate = webClient.get()
                    .uri(b -> b.path("/api/users/{u}/public-key").build(contact))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(java.time.Duration.ofMillis(300));  // Fixed

            if (candidate != null && !candidate.isBlank()) {
                // Validate base64 format
                if (candidate.matches("^[a-zA-Z0-9+/]+={0,2}$")) {
                    partnerB64 = candidate;
                    break;
                } else {
                    log.warn("Invalid base64 key format from {}", contact);
                }
            }
            Thread.sleep(300);
        }

        if (partnerB64 == null) {
            throw new RuntimeException("Timed out waiting for valid public key from " + contact);
        }

        // 4) reconstruct and agree
        partnerB64 = partnerB64.trim();
        if (partnerB64.length() % 4 != 0) {
            partnerB64 = partnerB64 + "=".repeat(4 - partnerB64.length() % 4);
        }

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
                String type = "TEXT";
                String ciphertextB64;
                String ivB64;
                if (key != null) {
                    // szyfrujemy tekst
                    byte[] encrypted = encryptMessage(message, key);
                    EncryptedMessage msg = EncryptedMessage.fromBytes(encrypted);
                    ciphertextB64 = msg.ciphertext();
                    ivB64 = msg.iv();
                } else {
                    // brak wspólnego klucza - nie powinniśmy wysyłać plaintext
                    Platform.runLater(() ->
                            updateChat("System", "Nie wykonano wymiany klucza – nie można wysłać wiadomości", false));
                    return;
                }

                MessageRequest req = new MessageRequest(
                        currentUser,
                        contact,
                        type,
                        ciphertextB64,
                        ivB64
                );
                webClient.post()
                        .uri("/api/messages")
                        .bodyValue(req)
                        .retrieve()
                        .toBodilessEntity()
                        .block();

                Platform.runLater(() -> updateChat("You", message, true));
            } catch (Exception e) {
                Platform.runLater(() ->
                        updateChat("System", "Send failed: " + e.getMessage(), false));
            }
        });
    }


}