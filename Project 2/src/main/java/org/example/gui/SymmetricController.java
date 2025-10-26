package org.example.gui;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import org.example.algoritmalar.Algoritmalar;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ResourceBundle;

public class SymmetricController implements Initializable {

    private String algoritma;
    public VBox mainMenu;
    public Stage stage;

    public Label keyInfo;
    public byte[] keyInfoBytes;
    public Label decryptInfo;
    public Label encryptMessageInfo;
    public byte[] encryptMessageInfoBytes;
    public String keyContent;
    public byte[] keyContentBytes;
    public String decryptContent;
    public byte[] decryptContentBytes;

    public File selectedFileSymmetricEncrypt;
    public String selectedFileSymmetricEncryptName;
    public File selectedFileSymmetricDecrypt;
    public String selectedFileSymmetricDecryptName;

    // Bilgilendirme Tab
    @FXML
    private TextArea symmetricExplanation;
    @FXML
    private Button processMenuForSymmetricButtonBack;

    // Metin Şifreleme Tab
    @FXML
    private Label encryptMessageExplanation;
    @FXML
    private Label keyInfoLabel;
    @FXML
    private TextArea encryptionMessageForSymmetric;
    @FXML
    private Button processMenuForSymmetricButtonEncrypt;
    @FXML
    private Button processMenuForSymmetricButtonEncryptActivate;
    @FXML
    private Button copyEncryptMessageButtonForSymmetric;
    @FXML
    private Button copyKeyButtonForSymmetric;
    @FXML
    private Label encryptedMessageInfoLabel;

    // Metin Çözme Tab
    @FXML
    private Label decryptMessageExplanation;
    @FXML
    private Label decryptKeyExplanation;
    @FXML
    private TextArea decryptionMessageForSymmetric;
    @FXML
    private TextArea decryptionKeyForSymmetric;
    @FXML
    private Button processMenuForSymmetricButtonDecrypt;
    @FXML
    private Button processMenuForSymmetricButtonDecryptActivate;
    @FXML
    private Button copyDecryptMessageButtonForSymmetric;
    @FXML
    private Label decryptionInfoLabel;

    // Dosya Şifreleme Tab
    @FXML
    private TextArea encryptionFileMessageForSymmetric;
    @FXML
    private Button processMenuForSymmetricButtonFileEncrypt;
    @FXML
    private Button processMenuForSymmetricButtonFileEncryptActivate;
    @FXML
    private Button saveEncryptFileButtonForSymmetric;
    @FXML
    private Button processMenuForSymmetricButtonFileEncryptEnter;
    @FXML
    private Button processMenuForSymmetricButtonFileEncryptEnterActivate;
    @FXML
    private Button copyKeyFileButtonForSymmetric;
    @FXML
    private Label encryptInfoLabel;

    // Dosya Çözme Tab
    @FXML
    private Label decryptInfoLabel;
    @FXML
    private TextArea decryptionFileMessageForSymmetric;
    @FXML
    private TextArea decryptionFileKeyForSymmetric;
    @FXML
    private Button processMenuForSymmetricButtonFileDecrypt;
    @FXML
    private Button processMenuForSymmetricButtonFileDecryptActivate;
    @FXML
    private Button saveDecryptFileButtonForSymmetric;
    @FXML
    private Button processMenuForSymmetricButtonFileDecryptEnter;
    @FXML
    private Button processMenuForSymmetricButtonFileDecryptEnterActivate;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        processMenuForSymmetricButtonBack.setDisable(false);
        processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonEncrypt.setDisable(false);
        processMenuForSymmetricButtonEncryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileEncrypt.setDisable(false);
        processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonDecrypt.setDisable(false);
        processMenuForSymmetricButtonDecryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecrypt.setDisable(false);
        processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
        encryptionMessageForSymmetric.setEditable(true);
        decryptionMessageForSymmetric.setEditable(true);
        decryptionKeyForSymmetric.setEditable(true);
        encryptionFileMessageForSymmetric.setEditable(false);
        decryptionFileMessageForSymmetric.setEditable(false);
        decryptionFileKeyForSymmetric.setEditable(true);
        copyKeyButtonForSymmetric.setVisible(false);
        copyKeyFileButtonForSymmetric.setVisible(false);
        copyEncryptMessageButtonForSymmetric.setVisible(false);
        saveEncryptFileButtonForSymmetric.setVisible(false);
        copyDecryptMessageButtonForSymmetric.setVisible(false);
        saveDecryptFileButtonForSymmetric.setVisible(false);
    }

    public void setAlgoritma(String algoritma) {
        this.algoritma = algoritma;
    }

    public void setMainMenu(VBox mainMenu) {
        this.mainMenu = mainMenu;
    }

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    @FXML
    private void processMenuForSymmetricButtonBack() {
        processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonEncrypt.setDisable(false);
        processMenuForSymmetricButtonEncryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileEncrypt.setDisable(false);
        processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonDecrypt.setDisable(false);
        processMenuForSymmetricButtonDecryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecrypt.setDisable(false);
        processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
        encryptionMessageForSymmetric.clear();
        encryptionMessageForSymmetric.setEditable(true);
        decryptionMessageForSymmetric.clear();
        decryptionMessageForSymmetric.setEditable(true);
        decryptionKeyForSymmetric.clear();
        decryptionKeyForSymmetric.setEditable(true);
        encryptionFileMessageForSymmetric.clear();
        encryptionFileMessageForSymmetric.setEditable(false);
        decryptionFileMessageForSymmetric.clear();
        decryptionFileMessageForSymmetric.setEditable(false);
        decryptionFileKeyForSymmetric.clear();
        decryptionFileKeyForSymmetric.setEditable(false);
        copyKeyButtonForSymmetric.setVisible(false);
        copyKeyFileButtonForSymmetric.setVisible(false);
        copyEncryptMessageButtonForSymmetric.setVisible(false);
        saveEncryptFileButtonForSymmetric.setVisible(false);
        copyDecryptMessageButtonForSymmetric.setVisible(false);
        saveDecryptFileButtonForSymmetric.setVisible(false);
        selectedFileSymmetricEncrypt = null;
        selectedFileSymmetricDecrypt = null;

        StackPane newContainer = new StackPane();
        newContainer.getChildren().add(mainMenu);
        Scene mainMenuScene = new Scene(newContainer);
        mainMenuScene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());
        stage.setScene(mainMenuScene);
        stage.setWidth(1200);
        stage.setHeight(900);
        stage.setResizable(false);
        stage.show();
    }

    // Metin Şifreleme Tab
    @FXML
    private void processMenuForSymmetricButtonEncrypt() {
        String userInputEncrypt = encryptionMessageForSymmetric.getText();
        try {
            keyContent = Algoritmalar.startMessage(algoritma, userInputEncrypt, "Şifrele", "Şifrele", "Şifrele", "Şifrele");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
        String[] keyInfoContent = keyContent.split("\n");

        if (keyContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Metni Girin");
            alertEntering.showAndWait();
            processMenuForSymmetricButtonEncrypt.setDisable(false);
            processMenuForSymmetricButtonEncryptActivate.setDisable(true);
            encryptionMessageForSymmetric.setEditable(true);
            copyKeyButtonForSymmetric.setVisible(false);
            copyEncryptMessageButtonForSymmetric.setVisible(false);
        }

        else {
            encryptMessageInfo = new Label(keyInfoContent[1]);
            keyInfo = new Label(keyInfoContent[0]);
            processMenuForSymmetricButtonEncrypt.setDisable(true);
            processMenuForSymmetricButtonEncryptActivate.setDisable(false);
            encryptionMessageForSymmetric.setEditable(false);
            copyKeyButtonForSymmetric.setVisible(true);
            copyEncryptMessageButtonForSymmetric.setVisible(true);
        }
    }

    @FXML
    private void processMenuForSymmetricButtonEncryptActivate() {
        processMenuForSymmetricButtonEncrypt.setDisable(false);
        processMenuForSymmetricButtonEncryptActivate.setDisable(true);
        encryptionMessageForSymmetric.setEditable(true);
        copyKeyButtonForSymmetric.setVisible(false);
        copyEncryptMessageButtonForSymmetric.setVisible(false);
    }

    @FXML
    private void copyEncryptMessageButtonForSymmetric() {
        String[] message = encryptMessageInfo.getText().split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(message[1]);
        clipboard.setContent(content);

        Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypt.setHeaderText("Şifreli Mesaj Kopyalandı");
        messageEncrypt.showAndWait();
    }

    @FXML
    private void copyKeyButtonForSymmetric() {
        String[] key = keyInfo.getText().split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(key[1]);
        clipboard.setContent(content);

        Alert keyCopy = new Alert(Alert.AlertType.INFORMATION);
        keyCopy.setHeaderText("Anahtar Kopyalandı");
        keyCopy.showAndWait();
    }

    // Metin Çözme Tab
    @FXML
    private void processMenuForSymmetricButtonDecrypt() {
        String userInputDecrypt = decryptionMessageForSymmetric.getText();
        String userInputKey = decryptionKeyForSymmetric.getText();
        try {
            decryptContent = Algoritmalar.startMessage(algoritma, "Çöz", "Çöz", userInputDecrypt, "Çöz", userInputKey);
        } catch (Exception error) {
            showErrorMessage("Girilen Şifreli Metin ya da Anahtar Hatalıdır.");
            throw new RuntimeException(error);
        }

        if (decryptContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Metni ve Anahtarı Girin");
            alertEntering.showAndWait();
            processMenuForSymmetricButtonDecrypt.setDisable(false);
            processMenuForSymmetricButtonDecryptActivate.setDisable(true);
            decryptionMessageForSymmetric.setEditable(true);
            decryptionKeyForSymmetric.setEditable(true);
            copyDecryptMessageButtonForSymmetric.setVisible(false);
        }

        else {
            decryptInfo = new Label(decryptContent);
            processMenuForSymmetricButtonDecrypt.setDisable(true);
            processMenuForSymmetricButtonDecryptActivate.setDisable(false);
            decryptionMessageForSymmetric.setEditable(false);
            decryptionKeyForSymmetric.setEditable(false);
            copyDecryptMessageButtonForSymmetric.setVisible(true);
        }
    }

    @FXML
    private void processMenuForSymmetricButtonDecryptActivate() {
        processMenuForSymmetricButtonDecrypt.setDisable(false);
        processMenuForSymmetricButtonDecryptActivate.setDisable(true);
        decryptionMessageForSymmetric.setEditable(true);
        decryptionKeyForSymmetric.setEditable(true);
        copyDecryptMessageButtonForSymmetric.setVisible(false);
    }

    @FXML
    private void copyDecryptMessageButtonForSymmetric() {
        String[] message = decryptInfo.getText().split("Şifresi çözülmüş metin oluşturuldu! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(message[1]);
        clipboard.setContent(content);

        Alert messageDecrypt = new Alert(Alert.AlertType.INFORMATION);
        messageDecrypt.setHeaderText("Şifresi Çözülmüş Mesaj Kopyalandı");
        messageDecrypt.showAndWait();
    }

    // Dosya Şifreleme Tab
    @FXML
    private void processMenuForSymmetricButtonFileEncryptEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSymmetricEncrypt = fileChooser.showOpenDialog(stage);
        if (selectedFileSymmetricEncrypt != null) {
            processMenuForSymmetricButtonFileEncryptEnter.setDisable(true);
            processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(false);
            processMenuForSymmetricButtonFileEncrypt.setDisable(false);
            processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
            encryptionFileMessageForSymmetric.setEditable(false);
            encryptionFileMessageForSymmetric.clear();
            selectedFileSymmetricEncryptName = selectedFileSymmetricEncrypt.getName();
            encryptionFileMessageForSymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileSymmetricEncryptName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonFileEncrypt.setDisable(false);
            processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
            encryptionFileMessageForSymmetric.setEditable(false);
            encryptionFileMessageForSymmetric.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSymmetricButtonFileEncryptEnterActivate() {
        processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonFileEncrypt.setDisable(false);
        processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
        encryptionFileMessageForSymmetric.setEditable(false);
        encryptionFileMessageForSymmetric.clear();
    }

    @FXML
    private void processMenuForSymmetricButtonFileEncrypt() {
        if (selectedFileSymmetricEncrypt != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileSymmetricEncrypt.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            try {
                keyContentBytes = Algoritmalar.startFile(algoritma, fileBytes, "Şifrele", null, null, "Şifrele");
            } catch (Exception error) {
                throw new RuntimeException(error);
            }

            if (keyContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
                processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonFileEncrypt.setDisable(false);
                processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
                encryptionFileMessageForSymmetric.setEditable(false);
            }

            else {
                String separate = bytesToHex(keyContentBytes);
                String[] parts = separate.split("012345677654321031");
                keyInfoBytes = hexToBytes(parts[0]);
                encryptMessageInfoBytes = hexToBytes(parts[1]);
                processMenuForSymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonFileEncrypt.setDisable(true);
                processMenuForSymmetricButtonFileEncryptActivate.setDisable(false);
                encryptionFileMessageForSymmetric.setEditable(false);
                copyKeyFileButtonForSymmetric.setVisible(true);
                saveEncryptFileButtonForSymmetric.setVisible(true);
            }
        }
        else {
            processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonFileEncrypt.setDisable(false);
            processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
            encryptionFileMessageForSymmetric.setEditable(false);
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSymmetricButtonFileEncryptActivate() {
        processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonFileEncrypt.setDisable(false);
        processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
        encryptionFileMessageForSymmetric.setEditable(false);
        saveEncryptFileButtonForSymmetric.setVisible(false);
        copyKeyFileButtonForSymmetric.setVisible(false);
    }

    @FXML
    private void saveEncryptFileButtonForSymmetric() {
        byte[] bytes = encryptMessageInfoBytes;
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Oluşturulan Şifreli Dosyayı Kaydet");
        fileChooser.setInitialFileName("sifreli_dosya");
        FileChooser.ExtensionFilter fileFormat = new FileChooser.ExtensionFilter("Şifrelenmiş Dosyalar", "*.bin");
        fileChooser.getExtensionFilters().add(fileFormat);
        fileChooser.getSelectedExtensionFilter();
        File file = fileChooser.showSaveDialog(stage);
        try {
            Files.write(file.toPath(), bytes);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypt.setHeaderText("Şifreli Dosya Kaydedildi");
        messageEncrypt.showAndWait();
    }

    @FXML
    private void copyKeyFileButtonForSymmetric() {
        String[] fileFormat = selectedFileSymmetricEncryptName.split("\\.");
        byte[] fileFormatBytes;
        try {
            fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
        } catch (UnsupportedEncodingException ee) {
            throw new RuntimeException(ee);
        }

        String keyInfoHex = bytesToHex(keyInfoBytes);
        String fileFormatHex = bytesToHex(fileFormatBytes);
        String finalKeyHex = keyInfoHex + ":" + fileFormatHex;

        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(finalKeyHex);
        clipboard.setContent(content);

        Alert keyCopy = new Alert(Alert.AlertType.INFORMATION);
        keyCopy.setHeaderText("Anahtar Kopyalandı");
        keyCopy.showAndWait();
    }

    // Dosya Çözme Tab
    @FXML
    private void processMenuForSymmetricButtonFileDecryptEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSymmetricDecrypt = fileChooser.showOpenDialog(stage);
        if (selectedFileSymmetricDecrypt != null) {
            processMenuForSymmetricButtonFileDecryptEnter.setDisable(true);
            processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(false);
            processMenuForSymmetricButtonFileDecrypt.setDisable(false);
            processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
            decryptionFileMessageForSymmetric.setEditable(false);
            decryptionFileMessageForSymmetric.clear();
            selectedFileSymmetricDecryptName = selectedFileSymmetricDecrypt.getName();
            decryptionFileMessageForSymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileSymmetricDecryptName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonFileDecrypt.setDisable(false);
            processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
            decryptionFileMessageForSymmetric.setEditable(false);
            decryptionFileMessageForSymmetric.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSymmetricButtonFileDecryptEnterActivate() {
        processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecrypt.setDisable(false);
        processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
        decryptionFileMessageForSymmetric.setEditable(false);
        decryptionFileMessageForSymmetric.clear();
    }

    @FXML
    private void processMenuForSymmetricButtonFileDecrypt() {
        if (selectedFileSymmetricDecrypt != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileSymmetricDecrypt.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            String userInputKey = decryptionFileKeyForSymmetric.getText();

            try {
                decryptContentBytes = Algoritmalar.startFile(algoritma, null, "Çöz", fileBytes, null, userInputKey);
            } catch (Exception error) {
                showErrorMessage("Girilen Şifreli Metin ya da Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (decryptContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonFileDecrypt.setDisable(false);
                processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
                decryptionFileMessageForSymmetric.setEditable(false);
                decryptionFileKeyForSymmetric.setEditable(true);
                saveDecryptFileButtonForSymmetric.setVisible(false);
            }

            else {
                processMenuForSymmetricButtonFileDecryptEnter.setDisable(true);
                processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonFileDecrypt.setDisable(true);
                processMenuForSymmetricButtonFileDecryptActivate.setDisable(false);
                decryptionFileMessageForSymmetric.setEditable(false);
                decryptionFileKeyForSymmetric.setEditable(false);
                saveDecryptFileButtonForSymmetric.setVisible(true);
            }
        }
        else {
            processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonFileDecrypt.setDisable(false);
            processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
            decryptionFileMessageForSymmetric.setEditable(false);
            decryptionFileKeyForSymmetric.setEditable(true);
            saveDecryptFileButtonForSymmetric.setVisible(false);
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Dosyayı ve Anahtarı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSymmetricButtonFileDecryptActivate() {
        processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecrypt.setDisable(false);
        processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
        decryptionFileMessageForSymmetric.setEditable(false);
        decryptionFileKeyForSymmetric.setEditable(true);
        saveDecryptFileButtonForSymmetric.setVisible(false);
    }

    @FXML
    private void saveDecryptFileButtonForSymmetric() {
        String separate = bytesToHex(decryptContentBytes);
        String[] parts = separate.split("012345677654321031");

        byte[] keyInfoBytes = hexToBytes(parts[0]);
        byte[] fileFormatBytes = hexToBytes(parts[1]);

        byte[] bytes = keyInfoBytes;
        byte[] fileNameFormatBytes = fileFormatBytes;
        String fileNameFormat = new String(fileNameFormatBytes, StandardCharsets.UTF_8);

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Çözülmüş Dosyayı Kaydet");
        fileChooser.setInitialFileName("cozulmus_dosya");
        FileChooser.ExtensionFilter fileFormat = new FileChooser.ExtensionFilter("Çözülmüş Dosyalar", "*." + fileNameFormat);
        fileChooser.getExtensionFilters().add(fileFormat);
        fileChooser.getSelectedExtensionFilter();
        File file = fileChooser.showSaveDialog(stage);
        try {
            Files.write(file.toPath(), bytes);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypt.setHeaderText("Şifresi Çözülmüş Dosya Kaydedildi");
        messageEncrypt.showAndWait();
    }

    public static void showErrorMessage(String message){
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Hata İle Karşılaşıldı.");
        alert.setHeaderText(message);
        alert.showAndWait();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Geçersiz hex formatı");
        }
        String hexLower = hex.toLowerCase();
        if (!hexLower.matches("[0-9a-f]+")) {
            throw new IllegalArgumentException("Geçersiz hex formatı: Sadece 0-9 ve a-f karakterleri kullanılabilir");
        }
        int len = hexLower.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexLower.charAt(i), 16) << 4)
                    + Character.digit(hexLower.charAt(i + 1), 16));
        }
        return data;
    }
}