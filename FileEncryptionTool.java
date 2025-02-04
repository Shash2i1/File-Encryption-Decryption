import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class FileEncryptionTool extends Application {

    private static final int AES_KEY_SIZE = 128;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";

    private SecretKey aesKey;
    private KeyPair rsaKeyPair;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("File Encryption and Decryption Tool");

        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setVgap(10);
        grid.setHgap(10);

        Label userLabel = new Label("Username:");
        TextField userField = new TextField();
        Label passwordLabel = new Label("Password:");
        PasswordField passwordField = new PasswordField();
        Button loginButton = new Button("Login");

        grid.add(userLabel, 0, 0);
        grid.add(userField, 1, 0);
        grid.add(passwordLabel, 0, 1);
        grid.add(passwordField, 1, 1);
        grid.add(loginButton, 1, 2);

        Scene loginScene = new Scene(grid, 400, 200);
        primaryStage.setScene(loginScene);

        // Initialize RSA key pair
        try {
            rsaKeyPair = generateRSAKeyPair();
        } catch (NoSuchAlgorithmException e) {
            showAlert(Alert.AlertType.ERROR, "Error", "Failed to generate RSA keys");
            return;
        }

        loginButton.setOnAction(event -> {
            String username = userField.getText();
            String password = passwordField.getText();

            if (authenticate(username, password)) {
                showMainInterface(primaryStage);
            } else {
                showAlert(Alert.AlertType.ERROR, "Authentication Failed", "Invalid username or password!");
            }
        });

        primaryStage.show();
    }

    private boolean authenticate(String username, String password) {
        return "shashank".equals(username) && "Pass@2003".equals(password);
    }

    private void showMainInterface(Stage primaryStage) {
        GridPane mainGrid = new GridPane();
        mainGrid.setPadding(new Insets(10));
        mainGrid.setVgap(10);
        mainGrid.setHgap(10);

        Button encryptButton = new Button("Encrypt File");
        Button decryptButton = new Button("Decrypt File");

        mainGrid.add(encryptButton, 0, 0);
        mainGrid.add(decryptButton, 1, 0);

        encryptButton.setOnAction(event -> encryptFile(primaryStage));
        decryptButton.setOnAction(event -> decryptFile(primaryStage));

        Scene mainScene = new Scene(mainGrid, 400, 200);
        primaryStage.setScene(mainScene);
    }

    private void encryptFile(Stage stage) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File to Encrypt");
        File file = fileChooser.showOpenDialog(stage);

        if (file != null) {
            try {
                aesKey = generateAESKey();
                byte[] encryptedData = encryptAES(Files.readAllBytes(file.toPath()), aesKey);
                byte[] encryptedAESKey = encryptRSA(aesKey.getEncoded(), rsaKeyPair.getPublic());

                saveToFile(file.getPath() + ".enc", encryptedAESKey, encryptedData);
                showAlert(Alert.AlertType.INFORMATION, "Success", "File encrypted successfully!");
            } catch (Exception e) {
                showAlert(Alert.AlertType.ERROR, "Error", "Failed to encrypt file: " + e.getMessage());
            }
        }
    }

    private void decryptFile(Stage stage) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File to Decrypt");
        File file = fileChooser.showOpenDialog(stage);

        if (file != null) {
            try (DataInputStream dis = new DataInputStream(new FileInputStream(file))) {
                int keyLength = dis.readInt();
                byte[] encryptedAESKey = new byte[keyLength];
                dis.readFully(encryptedAESKey);

                int dataLength = dis.readInt();
                byte[] encryptedData = new byte[dataLength];
                dis.readFully(encryptedData);

                byte[] aesKeyBytes = decryptRSA(encryptedAESKey, rsaKeyPair.getPrivate());
                aesKey = new SecretKeySpec(aesKeyBytes, AES_ALGORITHM);

                byte[] decryptedData = decryptAES(encryptedData, aesKey);
                Files.write(new File(file.getPath().replace(".enc", ".dec")).toPath(), decryptedData);

                showAlert(Alert.AlertType.INFORMATION, "Success", "File decrypted successfully!");
            } catch (Exception e) {
                showAlert(Alert.AlertType.ERROR, "Error", "Failed to decrypt file: " + e.getMessage());
            }
        }
    }

    private void saveToFile(String filePath, byte[] encryptedKey, byte[] encryptedData) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(filePath))) {
            dos.writeInt(encryptedKey.length);
            dos.write(encryptedKey);

            dos.writeInt(encryptedData.length);
            dos.write(encryptedData);
        }
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    private byte[] encryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private byte[] decryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private byte[] decryptRSA(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private void showAlert(Alert.AlertType alertType, String title, String message) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
