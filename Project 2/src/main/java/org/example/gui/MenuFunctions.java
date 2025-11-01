package org.example.gui;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.GridPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.example.algoritmalar.Algoritmalar;

import javax.smartcardio.Card;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class MenuFunctions extends MenuComponents {

    public ToggleGroup groupEncryptAndSignAndHashAndSmartCard;
    public ToggleGroup groupSymmetricAndAsymmetric;
    public ToggleGroup groupSymmetricOption;
    public ToggleGroup groupAsymmetricOption;
    public ToggleGroup groupSignOption;
    public ToggleGroup groupHashOption;
    public ToggleGroup groupSmartCardOption;


    public Stage stage;

    public Map<String, RadioButton> groupSymmetricOptionMap;
    public Map<String, RadioButton> groupAsymmetricOptionMap;
    public Map<String, RadioButton> groupSignOptionMap;
    public Map<String, RadioButton> groupHashOptionMap;
    public Map<String, RadioButton> groupSmartCardOptionMap;

    private RadioButton selectedMetodLast;

    public String algoritma;


    public String wrotedMessageEncrytionSymmetric;
    public String wrotedMessageDecryptionSymmetric;
    public Label keyInfo;
    public byte[] keyInfoBytes;
    public Label decryptInfo;
    public Label encryptMessageInfo;
    public byte[] encryptMessageInfoBytes;
    public Label encryptMessageExplanation;
    public Label decryptionMessageExplanation;
    public Label decryptionKeyExplanation;
    public String keyContent;
    public byte[] keyContentBytes;
    public String decryptContent;
    public byte[] decryptContentBytes;


    public String wrotedMessageEncrytionAsymmetric;
    public String wrotedMessageDecryptionAsymmetric;
    public Label encryptKeyInfo;
    public byte[] encryptKeyInfoBytes;
    public byte[] publicKeyInfoBytes;
    public byte[] publicKeyfileFormatBytes;
    public Label encryptKeyExplanation;
    public Label decryptionInfo;
    public Label decryptKeyInfo;
    public byte[] decryptKeyInfoBytes;
    public Label decryptKeyExplanation;
    public Label encryptedMessageInfo;
    public Label decryptMessageExplanation;
    public String encryptionContent;
    public byte[] encryptionContentBytes;
    public String decryptinContent;
    public byte[] decryptionContentBytes;


    public String wrotedMessageSigning;
    public String wrotedMessageValidating;
    public String wrotedSignedMessage;
    public Label keysExplanation;
    public byte[] privateKeyInfoBytes;
    public byte[] privateKeyfileFormatBytes;
    public Label signedMessageInfo;
    public Label signKeyInfo;
    public byte[] signKeyInfoBytes;
    public Label signKeyExplanation;
    public Label signMessageExplanation;
    public Label validateKeyInfo;
    public byte[] validateKeyInfoBytes;
    public Label validateKeyExplanation;
    public Label validateMessageExplanation;
    public Label validateSignatureExplanation;
    public String keysContent;
    public byte[] keysContentBytes;
    public String signContent;
    public byte[] signContentBytes;
    public String validateContent;
    public byte[] validateContentBytes;


    public String wrotedMessageHashing;
    public String wrotedMessageMatching;
    public Label hashInfo;
    public Label hashExplanation;
    public Label hashMessageExplanation;
    public Label matchMessageExplanation;
    public String hashContent;
    public byte[] hashContentBytes;
    public String matchContent;
    public byte[] matchContentBytes;


    public MenuFunctions(Stage stage){
        this.stage = stage;
        initializeToggleGroups();
        initializeActions();
    }


    private void initializeToggleGroups(){

        groupEncryptAndSignAndHashAndSmartCard = new ToggleGroup();
        encryptOption.setToggleGroup(groupEncryptAndSignAndHashAndSmartCard);
        signOption.setToggleGroup(groupEncryptAndSignAndHashAndSmartCard);
        hashOption.setToggleGroup(groupEncryptAndSignAndHashAndSmartCard);
        smartCardOption.setToggleGroup(groupEncryptAndSignAndHashAndSmartCard);

        groupSymmetricAndAsymmetric = new ToggleGroup();
        symmetricOption.setToggleGroup(groupSymmetricAndAsymmetric);
        asymmetricOption.setToggleGroup(groupSymmetricAndAsymmetric);

        groupSymmetricOption = new ToggleGroup();
        desOption.setToggleGroup(groupSymmetricOption);
        threeDesOption.setToggleGroup(groupSymmetricOption);
        aesOption.setToggleGroup(groupSymmetricOption);

        groupAsymmetricOption = new ToggleGroup();
        rsaOptionEncrypt.setToggleGroup(groupAsymmetricOption);
        eciesOption.setToggleGroup(groupAsymmetricOption);

        groupSignOption = new ToggleGroup();
        rsaOptionSign.setToggleGroup(groupSignOption);
        ecdsaOption.setToggleGroup(groupSignOption);
        dsaOption.setToggleGroup(groupSignOption);

        groupHashOption = new ToggleGroup();
        md5Option.setToggleGroup(groupHashOption);
        sha1Option.setToggleGroup(groupHashOption);
        sha256Option.setToggleGroup(groupHashOption);
        sha3Option.setToggleGroup(groupHashOption);
        sha512Option.setToggleGroup(groupHashOption);
        blake2Option.setToggleGroup(groupHashOption);
        argon2Option.setToggleGroup(groupHashOption);

        groupSymmetricOptionMap = new HashMap<>();
        groupSymmetricOptionMap.put("DES Algoritması", desOption);
        groupSymmetricOptionMap.put("3DES Algoritması", threeDesOption);
        groupSymmetricOptionMap.put("AES Algoritması", aesOption);

        groupAsymmetricOptionMap = new HashMap<>();
        groupAsymmetricOptionMap.put("RSA Algoritması", rsaOptionEncrypt);
        groupAsymmetricOptionMap.put("ECIES Algoritması", eciesOption);

        groupSignOptionMap = new HashMap<>();
        groupSignOptionMap.put("RSA Algoritması", rsaOptionSign);
        groupSignOptionMap.put("ECDSA Algoritması", ecdsaOption);
        groupSignOptionMap.put("DSA Algoritması", dsaOption);

        groupHashOptionMap = new HashMap<>();
        groupHashOptionMap.put("MD5 Algoritması", md5Option);
        groupHashOptionMap.put("SHA-1 Algoritması", sha1Option);
        groupHashOptionMap.put("SHA-256 Algoritması", sha256Option);
        groupHashOptionMap.put("SHA-3 Algoritması", sha3Option);
        groupHashOptionMap.put("SHA-512 Algoritması", sha512Option);
        groupHashOptionMap.put("BLAKE2 Algoritması", blake2Option);
        groupHashOptionMap.put("Argon2 Algoritması", argon2Option);

        groupSmartCardOptionMap = new  HashMap<>();
        groupSmartCardOptionMap.put("Akıllı Kart Sertifika İşlemleri", smartCardOption);
    }


    private void initializeActions(){
        encryptOption.setOnAction(e -> {
            encryptSubMenu.setVisible(true);
            signSubMenu.setVisible(false);
            hashSubMenu.setVisible(false);
            clearSelections(groupSymmetricAndAsymmetric, groupSymmetricOption, groupAsymmetricOption, groupSignOption, groupHashOption);
            updateConfirmButtonState(null, 0);
        });

        symmetricOption.setOnAction(e -> {
            symmetricSubMenu.setVisible(true);
            asymmetricSubMenu.setVisible(false);
            clearSelections(groupAsymmetricOption, groupSignOption, groupHashOption);
            updateConfirmButtonState(null, 0);
        });

        asymmetricOption.setOnAction(e -> {
            symmetricSubMenu.setVisible(false);
            asymmetricSubMenu.setVisible(true);
            clearSelections(groupSymmetricOption, groupSignOption, groupHashOption);
            updateConfirmButtonState(null, 0);
        });

        signOption.setOnAction(e -> {
            encryptSubMenu.setVisible(false);
            symmetricSubMenu.setVisible(false);
            asymmetricSubMenu.setVisible(false);
            signSubMenu.setVisible(true);
            hashSubMenu.setVisible(false);
            clearSelections(groupSymmetricAndAsymmetric, groupSymmetricOption, groupAsymmetricOption, groupHashOption);
            updateConfirmButtonState(null, 0);
        });

        hashOption.setOnAction(e -> {
            encryptSubMenu.setVisible(false);
            symmetricSubMenu.setVisible(false);
            asymmetricSubMenu.setVisible(false);
            signSubMenu.setVisible(false);
            hashSubMenu.setVisible(true);
            clearSelections(groupSymmetricAndAsymmetric, groupSymmetricOption, groupAsymmetricOption, groupSignOption);
            updateConfirmButtonState(null, 0);
        });

        smartCardOption.setOnAction(e -> {
            encryptSubMenu.setVisible(false);
            symmetricSubMenu.setVisible(false);
            asymmetricSubMenu.setVisible(false);
            signSubMenu.setVisible(false);
            hashSubMenu.setVisible(false);
            clearSelections(groupSymmetricAndAsymmetric, groupSymmetricOption, groupAsymmetricOption, groupSignOption, groupHashOption);
            RadioButton selectedMetod = ((RadioButton) e.getSource());
            updateConfirmButtonState(selectedMetod, 1);
        });

        groupSymmetricOption.getToggles().forEach(toggle -> {
            ((RadioButton)toggle).setOnAction(e -> {
                String selectedText = ((RadioButton) e.getSource()).getText();
                RadioButton selectedMetod = groupSymmetricOptionMap.get(selectedText);
                updateConfirmButtonState(selectedMetod, 1);
            });
        });

        groupAsymmetricOption.getToggles().forEach(toggle -> {
            ((RadioButton)toggle).setOnAction(e -> {
                String selectedText = ((RadioButton) e.getSource()).getText();
                RadioButton selectedMetod = groupAsymmetricOptionMap.get(selectedText);
                updateConfirmButtonState(selectedMetod, 1);
            });
        });

        groupSignOption.getToggles().forEach(toggle -> {
            ((RadioButton)toggle).setOnAction(e -> {
                String selectedText = ((RadioButton) e.getSource()).getText();
                RadioButton selectedMetod = groupSignOptionMap.get(selectedText);
                updateConfirmButtonState(selectedMetod, 1);
            });
        });

        groupHashOption.getToggles().forEach(toggle -> {
            ((RadioButton)toggle).setOnAction(e -> {
                String selectedText = ((RadioButton) e.getSource()).getText();
                RadioButton selectedMetod = groupHashOptionMap.get(selectedText);
                updateConfirmButtonState(selectedMetod, 1);
            });
        });

        confirmButton.setOnAction(e -> {
            String[] whichMenu = getSelectedAlgorithm().split(" ");

            if (whichMenu[0].equals("Simetrik")) {
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/symmetric.fxml"));
                Parent root = null;
                try {
                    root = loader.load();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                SymmetricController controller = loader.getController();

                controller.setAlgoritma(getSelectedAlgorithm());
                controller.setMainMenu(mainMenu);
                controller.setStage(stage);

                Scene scene = new Scene(root, 1200, 900);
                stage.setTitle("Şifreleme ve İmzalama Uygulaması - " + getSelectedAlgorithm());
                stage.setScene(scene);
                stage.show();
            }

            if (whichMenu[0].equals("Asimetrik")) {
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/asymmetric.fxml"));
                Parent root = null;
                try {
                    root = loader.load();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                AsymmetricController controller = loader.getController();

                controller.setAlgoritma(getSelectedAlgorithm());
                controller.setMainMenu(mainMenu);
                controller.setStage(stage);

                Scene scene = new Scene(root, 1200, 900);
                stage.setTitle("Şifreleme ve İmzalama Uygulaması - " + getSelectedAlgorithm());
                stage.setScene(scene);
                stage.show();
            }

            if (whichMenu[0].equals("İmzalama:")) {
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/sign.fxml"));
                Parent root = null;
                try {
                    root = loader.load();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                SignController controller = loader.getController();

                controller.setAlgoritma(getSelectedAlgorithm());
                controller.setMainMenu(mainMenu);
                controller.setStage(stage);

                Scene scene = new Scene(root, 1200, 900);
                stage.setTitle("Şifreleme ve İmzalama Uygulaması - " + getSelectedAlgorithm());
                stage.setScene(scene);
                stage.show();
            }

            if (whichMenu[0].equals("Hash:")) {
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/hash.fxml"));
                Parent root = null;
                try {
                    root = loader.load();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                HashController controller = loader.getController();

                controller.setAlgoritma(getSelectedAlgorithm());
                controller.setMainMenu(mainMenu);
                controller.setStage(stage);

                Scene scene = new Scene(root, 1200, 900);
                stage.setTitle("Şifreleme ve İmzalama Uygulaması - " + getSelectedAlgorithm());
                stage.setScene(scene);
                stage.show();
            }

            if (whichMenu[0].equals("Akıllı")) {
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/smartcard.fxml"));
                Parent root = null;
                try {
                    root = loader.load();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                SmartCardController controller = loader.getController();

                controller.setAlgoritma(getSelectedAlgorithm());
                controller.setMainMenu(mainMenu);
                controller.setStage(stage);

                Scene scene = new Scene(root, 1200, 900);
                stage.setTitle("Şifreleme ve İmzalama Uygulaması - " + getSelectedAlgorithm());
                stage.setScene(scene);
                stage.show();
            }
        });










        processMenuForSymmetricButtonBack.setOnAction(e -> {
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
            copyKeyButtonForSymmetric.setVisible(false);
            copyKeyFileButtonForSymmetric.setVisible(false);
            copyEncryptMessageButtonForSymmetric.setVisible(false);
            saveEncryptFileButtonForSymmetric.setVisible(false);
            copyDecryptMessageButtonForSymmetric.setVisible(false);
            saveDecryptFileButtonForSymmetric.setVisible(false);
            processMenuForSymmetric.getChildren().clear();
            selectedFile = null;
            stage.getScene().setRoot(mainMenu);
        });

        processMenuForSymmetricButtonFileEncryptEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageEncrytionSymmetric = encryptionMessageForSymmetric.getText();
            if (selectedFile != null) {
                processMenuForSymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(false);
                processMenuForSymmetricButtonEncrypt.setDisable(true);
                processMenuForSymmetricButtonEncryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileEncrypt.setDisable(false);
                processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
                encryptionMessageForSymmetric.setEditable(false);
                encryptionMessageForSymmetric.clear();
                selectedFileName = selectedFile.getName();
                encryptionMessageForSymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonEncrypt.setDisable(false);
                processMenuForSymmetricButtonEncryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileEncrypt.setDisable(false);
                processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
                encryptionMessageForSymmetric.setEditable(true);
                encryptionMessageForSymmetric.clear();
                encryptionMessageForSymmetric.appendText(wrotedMessageEncrytionSymmetric);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSymmetricButtonFileEncryptEnterActivate.setOnAction(e -> {
            processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonEncrypt.setDisable(false);
            processMenuForSymmetricButtonEncryptActivate.setDisable(true);
            processMenuForSymmetricButtonFileEncrypt.setDisable(false);
            processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
            encryptionMessageForSymmetric.setEditable(true);
            encryptionMessageForSymmetric.clear();
            encryptionMessageForSymmetric.appendText(wrotedMessageEncrytionSymmetric);
        });

        processMenuForSymmetricButtonEncrypt.setOnAction(e -> {
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
                processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonEncrypt.setDisable(false);
                processMenuForSymmetricButtonEncryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileEncrypt.setDisable(false);
                processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
                encryptionMessageForSymmetric.setEditable(true);
                copyKeyButtonForSymmetric.setVisible(false);
                copyEncryptMessageButtonForSymmetric.setVisible(false);
            }

            else {
                encryptMessageInfo = new Label(keyInfoContent[1]);
                String[] parts1 = encryptMessageInfo.getText().split("! ");
                Label encryptMessageInfoLabel = new Label(parts1[0] + "!");
                firstGridSymmetric = new GridPane();
                firstGridSymmetric.add(encryptMessageInfoLabel, 0, 0);
                firstGridSymmetric.add(copyEncryptMessageButtonForSymmetric, 1, 0);
                firstGridSymmetric.setHgap(5);
                keyInfo = new Label(keyInfoContent[0]);
                String[] parts2 = keyInfo.getText().split("! ");
                Label keyInfoLabel = new Label(parts2[0] + "!");
                secondGridSymmetric = new GridPane();
                secondGridSymmetric.add(keyInfoLabel, 0, 0);
                secondGridSymmetric.add(copyKeyButtonForSymmetric, 1, 0);
                secondGridSymmetric.setHgap(5);
                processMenuForSymmetric.getChildren().addAll(firstGridSymmetric, secondGridSymmetric);
                processMenuForSymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonFileEncrypt.setDisable(true);
                processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
                processMenuForSymmetricButtonEncrypt.setDisable(true);
                processMenuForSymmetricButtonEncryptActivate.setDisable(false);
                encryptionMessageForSymmetric.setEditable(false);
                copyKeyButtonForSymmetric.setVisible(true);
                copyEncryptMessageButtonForSymmetric.setVisible(true);
            }
        });

        processMenuForSymmetricButtonEncryptActivate.setOnAction(e -> {
            processMenuForSymmetric.getChildren().removeAll(firstGridSymmetric, secondGridSymmetric);
            processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonEncrypt.setDisable(false);
            processMenuForSymmetricButtonEncryptActivate.setDisable(true);
            processMenuForSymmetricButtonFileEncrypt.setDisable(false);
            processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
            encryptionMessageForSymmetric.setEditable(true);
        });

        processMenuForSymmetricButtonFileEncrypt.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytes;
                try {
                    fileBytes = Files.readAllBytes(selectedFile.toPath());
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
                    processMenuForSymmetricButtonEncrypt.setDisable(false);
                    processMenuForSymmetricButtonEncryptActivate.setDisable(true);
                    processMenuForSymmetricButtonFileEncrypt.setDisable(false);
                    processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
                    encryptionMessageForSymmetric.setEditable(true);
                }

                else {
                    String separate = bytesToHex(keyContentBytes);
                    String[] parts = separate.split("012345677654321031");
                    keyInfoBytes = hexToBytes(parts[0]);
                    Label encryptMessageInfoLabel = new Label("Dosya şifrelendi!");
                    firstGridSymmetric = new GridPane();
                    firstGridSymmetric.add(encryptMessageInfoLabel, 0, 0);
                    firstGridSymmetric.add(saveEncryptFileButtonForSymmetric, 1, 0);
                    firstGridSymmetric.setHgap(5);
                    Label keyInfoLabel = new Label("Anahtar oluşturuldu!");
                    encryptMessageInfoBytes = hexToBytes(parts[1]);
                    secondGridSymmetric = new GridPane();
                    secondGridSymmetric.add(keyInfoLabel, 0, 0);
                    secondGridSymmetric.add(copyKeyFileButtonForSymmetric, 1, 0);
                    secondGridSymmetric.setHgap(5);
                    processMenuForSymmetric.getChildren().addAll(firstGridSymmetric, secondGridSymmetric);
                    processMenuForSymmetricButtonFileEncryptEnter.setDisable(true);
                    processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
                    processMenuForSymmetricButtonFileEncrypt.setDisable(true);
                    processMenuForSymmetricButtonFileEncryptActivate.setDisable(false);
                    processMenuForSymmetricButtonEncrypt.setDisable(true);
                    processMenuForSymmetricButtonEncryptActivate.setDisable(true);
                    encryptionMessageForSymmetric.setEditable(false);
                    copyKeyFileButtonForSymmetric.setVisible(true);
                    saveEncryptFileButtonForSymmetric.setVisible(true);
                }
            }
            else {
                processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonEncrypt.setDisable(false);
                processMenuForSymmetricButtonEncryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileEncrypt.setDisable(false);
                processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
                encryptionMessageForSymmetric.setEditable(true);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSymmetricButtonFileEncryptActivate.setOnAction(e -> {
            processMenuForSymmetric.getChildren().removeAll(firstGridSymmetric, secondGridSymmetric);
            processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonEncrypt.setDisable(false);
            processMenuForSymmetricButtonEncryptActivate.setDisable(true);
            processMenuForSymmetricButtonFileEncrypt.setDisable(false);
            processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
            encryptionMessageForSymmetric.setEditable(true);
        });

        processMenuForSymmetricButtonFileDecryptEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageDecryptionSymmetric = decryptionMessageForSymmetric.getText();
            if (selectedFile != null) {
                processMenuForSymmetricButtonFileDecryptEnter.setDisable(true);
                processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(false);
                processMenuForSymmetricButtonDecrypt.setDisable(true);
                processMenuForSymmetricButtonDecryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileDecrypt.setDisable(false);
                processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
                decryptionMessageForSymmetric.setEditable(false);
                decryptionMessageForSymmetric.clear();
                selectedFileName = selectedFile.getName();
                decryptionMessageForSymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonDecrypt.setDisable(false);
                processMenuForSymmetricButtonDecryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileDecrypt.setDisable(false);
                processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
                decryptionMessageForSymmetric.setEditable(true);
                decryptionMessageForSymmetric.clear();
                decryptionMessageForSymmetric.appendText(wrotedMessageDecryptionSymmetric);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSymmetricButtonFileDecryptEnterActivate.setOnAction(e -> {
            processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonDecrypt.setDisable(false);
            processMenuForSymmetricButtonDecryptActivate.setDisable(true);
            processMenuForSymmetricButtonFileDecrypt.setDisable(false);
            processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
            decryptionMessageForSymmetric.setEditable(true);
            decryptionMessageForSymmetric.clear();
            decryptionMessageForSymmetric.appendText(wrotedMessageDecryptionSymmetric);
        });

        processMenuForSymmetricButtonDecrypt.setOnAction(e -> {
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
                processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonDecrypt.setDisable(false);
                processMenuForSymmetricButtonDecryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileDecrypt.setDisable(false);
                processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
                decryptionMessageForSymmetric.setEditable(true);
                decryptionKeyForSymmetric.setEditable(true);
                copyDecryptMessageButtonForSymmetric.setVisible(false);
            }

            else {
                decryptInfo = new Label(decryptContent);
                String[] parts1 = decryptInfo.getText().split("! ");
                Label decryptInfoLabel = new Label(parts1[0] + "!");
                thirdGridSymmetric = new GridPane();
                thirdGridSymmetric.add(decryptInfoLabel, 0, 1);
                thirdGridSymmetric.add(copyDecryptMessageButtonForSymmetric, 1, 1);
                thirdGridSymmetric.setHgap(5);
                processMenuForSymmetric.getChildren().add(thirdGridSymmetric);
                processMenuForSymmetricButtonFileDecryptEnter.setDisable(true);
                processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonDecrypt.setDisable(true);
                processMenuForSymmetricButtonDecryptActivate.setDisable(false);
                processMenuForSymmetricButtonFileDecrypt.setDisable(true);
                processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
                decryptionMessageForSymmetric.setEditable(false);
                decryptionKeyForSymmetric.setEditable(false);
                copyDecryptMessageButtonForSymmetric.setVisible(true);
            }
        });

        processMenuForSymmetricButtonDecryptActivate.setOnAction(e -> {
            processMenuForSymmetric.getChildren().removeAll(thirdGridSymmetric);
            processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonDecrypt.setDisable(false);
            processMenuForSymmetricButtonDecryptActivate.setDisable(true);
            processMenuForSymmetricButtonFileDecrypt.setDisable(false);
            processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
            decryptionMessageForSymmetric.setEditable(true);
            decryptionKeyForSymmetric.setEditable(true);
        });

        processMenuForSymmetricButtonFileDecrypt.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytes;
                try {
                    fileBytes = Files.readAllBytes(selectedFile.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                String userInputKey = decryptionKeyForSymmetric.getText();

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
                    processMenuForSymmetricButtonDecrypt.setDisable(true);
                    processMenuForSymmetricButtonDecryptActivate.setDisable(true);
                    processMenuForSymmetricButtonFileDecrypt.setDisable(false);
                    processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
                    decryptionMessageForSymmetric.setEditable(true);
                    decryptionKeyForSymmetric.setEditable(true);
                    saveDecryptFileButtonForSymmetric.setVisible(false);
                }

                else {
                    Label decryptInfoLabel = new Label("Dosya çözüldü!");
                    thirdGridSymmetric = new GridPane();
                    thirdGridSymmetric.add(decryptInfoLabel, 0, 1);
                    thirdGridSymmetric.add(saveDecryptFileButtonForSymmetric, 1, 1);
                    thirdGridSymmetric.setHgap(5);
                    processMenuForSymmetric.getChildren().add(thirdGridSymmetric);
                    processMenuForSymmetricButtonFileDecryptEnter.setDisable(true);
                    processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
                    processMenuForSymmetricButtonDecrypt.setDisable(true);
                    processMenuForSymmetricButtonDecryptActivate.setDisable(true);
                    processMenuForSymmetricButtonFileDecrypt.setDisable(true);
                    processMenuForSymmetricButtonFileDecryptActivate.setDisable(false);
                    decryptionMessageForSymmetric.setEditable(false);
                    decryptionKeyForSymmetric.setEditable(false);
                    saveDecryptFileButtonForSymmetric.setVisible(true);
                }
            }
            else {
                processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
                processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForSymmetricButtonDecrypt.setDisable(false);
                processMenuForSymmetricButtonDecryptActivate.setDisable(true);
                processMenuForSymmetricButtonFileDecrypt.setDisable(false);
                processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
                decryptionMessageForSymmetric.setEditable(true);
                decryptionKeyForSymmetric.setEditable(true);
                saveDecryptFileButtonForSymmetric.setVisible(false);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSymmetricButtonFileDecryptActivate.setOnAction(e -> {
            processMenuForSymmetric.getChildren().removeAll(thirdGridSymmetric);
            processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForSymmetricButtonDecrypt.setDisable(false);
            processMenuForSymmetricButtonDecryptActivate.setDisable(true);
            processMenuForSymmetricButtonFileDecrypt.setDisable(false);
            processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
            decryptionMessageForSymmetric.setEditable(true);
            decryptionKeyForSymmetric.setEditable(true);
            saveDecryptFileButtonForSymmetric.setVisible(false);
        });

        copyKeyButtonForSymmetric.setOnAction(e -> {
            String[] key = keyInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(key[1]);
            clipboard.setContent(content);

            Alert keyCopy = new Alert(Alert.AlertType.INFORMATION);
            keyCopy.setHeaderText("Anahtar Kopyalandı");
            keyCopy.showAndWait();
        });

        copyKeyFileButtonForSymmetric.setOnAction(e -> {
            String[] fileFormat = selectedFileName.split("\\.");
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
        });

        copyEncryptMessageButtonForSymmetric.setOnAction(e -> {
            String[] message = encryptMessageInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(message[1]);
            clipboard.setContent(content);

            Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
            messageEncrypt.setHeaderText("Şifreli Mesaj Kopyalandı");
            messageEncrypt.showAndWait();
        });

        saveEncryptFileButtonForSymmetric.setOnAction(e -> {
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
        });

        copyDecryptMessageButtonForSymmetric.setOnAction(e -> {
            String[] message = decryptInfo.getText().split("Şifresi çözülmüş metin oluşturuldu! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(message[1]);
            clipboard.setContent(content);

            Alert messageDecrypt = new Alert(Alert.AlertType.INFORMATION);
            messageDecrypt.setHeaderText("Şifresi Çözülmüş Mesaj Kopyalandı");
            messageDecrypt.showAndWait();
        });

        saveDecryptFileButtonForSymmetric.setOnAction(e -> {
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
        });










        processMenuForAsymmetricButtonBack.setOnAction(e -> {
            processMenuForAsymmetricButtonGenerateKeys.setDisable(false);
            processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysFile.setDisable(false);
            processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
            processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonEncrypt.setDisable(false);
            processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonDecrypt.setDisable(false);
            processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
            encryptMessageForAsymmetric.clear();
            encryptMessageForAsymmetric.setEditable(true);
            encryptKeyForAsymmetric.clear();
            encryptKeyForAsymmetric.setEditable(true);
            decryptMessageForAsymmetric.clear();
            decryptMessageForAsymmetric.setEditable(true);
            decryptKeyForAsymmetric.clear();
            decryptKeyForAsymmetric.setEditable(true);
            copyEncryptKeyButtonForAsymmetric.setVisible(false);
            copyDecryptKeyButtonForAsymmetric.setVisible(false);
            copyEncryptedMessageButtonForAsymmetric.setVisible(false);
            saveEncryptFileButtonForAsymmetric.setVisible(false);
            copyDecryptedMessageButtonForAsymmetric.setVisible(false);
            saveDecryptFileButtonForAsymmetric.setVisible(false);
            processMenuForAsymmetric.getChildren().clear();
            selectedFile = null;
            stage.getScene().setRoot(mainMenu);
        });

        processMenuForAsymmetricButtonGenerateKeys.setOnAction(e -> {
            try {
                keysContent = Algoritmalar.startMessage(algoritma, "Anahtar", "Anahtar", "Anahtar", "Anahtar", "Anahtar");
            } catch (Exception error) {
                throw new RuntimeException(error);
            }
            String[] keysInfoContent = keysContent.split("\n");


            encryptKeyInfo = new Label(keysInfoContent[0]);
            String[] parts1 = encryptKeyInfo.getText().split("! ");
            Label encryptKeyInfoLabel = new Label(parts1[0] + "!");
            firstGridAsymmetric = new GridPane();
            firstGridAsymmetric.add(encryptKeyInfoLabel, 0, 0);
            firstGridAsymmetric.add(copyEncryptKeyButtonForAsymmetric, 1, 0);
            firstGridAsymmetric.setHgap(5);
            decryptKeyInfo = new Label(keysInfoContent[1]);
            String[] parts2 = decryptKeyInfo.getText().split("! ");
            Label decryptKeyInfoLabel = new Label(parts2[0] + "!");
            secondGridAsymmetric = new GridPane();
            secondGridAsymmetric.add(decryptKeyInfoLabel, 0, 0);
            secondGridAsymmetric.add(copyDecryptKeyButtonForAsymmetric, 1, 0);
            secondGridAsymmetric.setHgap(5);
            processMenuForAsymmetric.getChildren().addAll(firstGridAsymmetric, secondGridAsymmetric);
            processMenuForAsymmetricButtonGenerateKeys.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(false);
            processMenuForAsymmetricButtonGenerateKeysFile.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
            copyEncryptKeyButtonForAsymmetric.setVisible(true);
            copyDecryptKeyButtonForAsymmetric.setVisible(true);
        });

        processMenuForAsymmetricButtonGenerateKeysActivate.setOnAction(e -> {
            processMenuForAsymmetric.getChildren().removeAll(firstGridAsymmetric, secondGridAsymmetric);
            processMenuForAsymmetricButtonGenerateKeys.setDisable(false);
            processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysFile.setDisable(false);
            processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
            copyEncryptKeyButtonForAsymmetric.setVisible(false);
            copyDecryptKeyButtonForAsymmetric.setVisible(false);
        });

        processMenuForAsymmetricButtonGenerateKeysFile.setOnAction(e -> {
            try {
                keysContentBytes = Algoritmalar.startFile(algoritma, null, "Anahtar", null, null, "Anahtar");
            } catch (Exception error) {
                throw new RuntimeException(error);
            }
            String keysInfoContent = bytesToHex(keysContentBytes);
            String[] partsPublicAndPrivate = keysInfoContent.split("012345677654321031012345677654321031");


            encryptKeyInfoBytes = hexToBytes(partsPublicAndPrivate[0]);
            Label encryptKeyInfoLabel = new Label("Genel anahtar oluşturuldu!");
            firstGridAsymmetric = new GridPane();
            firstGridAsymmetric.add(encryptKeyInfoLabel, 0, 0);
            firstGridAsymmetric.add(copyEncryptKeyFileButtonForAsymmetric, 1, 0);
            firstGridAsymmetric.setHgap(5);
            decryptKeyInfoBytes = hexToBytes(partsPublicAndPrivate[1]);
            Label decryptKeyInfoLabel = new Label("Özel anahtar oluşturuldu!");
            secondGridAsymmetric = new GridPane();
            secondGridAsymmetric.add(decryptKeyInfoLabel, 0, 0);
            secondGridAsymmetric.add(copyDecryptKeyFileButtonForAsymmetric, 1, 0);
            secondGridAsymmetric.setHgap(5);
            processMenuForAsymmetric.getChildren().addAll(firstGridAsymmetric, secondGridAsymmetric);
            processMenuForAsymmetricButtonGenerateKeys.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysFile.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(false);
            copyEncryptKeyFileButtonForAsymmetric.setVisible(true);
            copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
        });

        processMenuForAsymmetricButtonGenerateKeysFileActivate.setOnAction(e -> {
            processMenuForAsymmetric.getChildren().removeAll(firstGridAsymmetric, secondGridAsymmetric);
            processMenuForAsymmetricButtonGenerateKeys.setDisable(false);
            processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
            processMenuForAsymmetricButtonGenerateKeysFile.setDisable(false);
            processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
            copyEncryptKeyFileButtonForAsymmetric.setVisible(false);
            copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
        });

        processMenuForAsymmetricButtonFileEncryptEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageEncrytionAsymmetric = encryptMessageForAsymmetric.getText();
            if (selectedFile != null) {
                processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(false);
                processMenuForAsymmetricButtonEncrypt.setDisable(true);
                processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
                processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
                encryptMessageForAsymmetric.setEditable(false);
                encryptKeyForAsymmetric.setEditable(true);
                encryptMessageForAsymmetric.clear();
                selectedFileName = selectedFile.getName();
                encryptMessageForAsymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonEncrypt.setDisable(false);
                processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
                processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
                encryptMessageForAsymmetric.setEditable(true);
                encryptKeyForAsymmetric.setEditable(true);
                encryptMessageForAsymmetric.clear();
                encryptMessageForAsymmetric.appendText(wrotedMessageEncrytionAsymmetric);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForAsymmetricButtonFileEncryptEnterActivate.setOnAction(e -> {
            processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonEncrypt.setDisable(false);
            processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
            encryptMessageForAsymmetric.setEditable(true);
            encryptKeyForAsymmetric.setEditable(true);
            encryptMessageForAsymmetric.clear();
            encryptMessageForAsymmetric.appendText(wrotedMessageEncrytionAsymmetric);
        });

        processMenuForAsymmetricButtonEncrypt.setOnAction(e -> {
            String userInputEncryptMessage = encryptMessageForAsymmetric.getText();
            String userInputEncryptKey = encryptKeyForAsymmetric.getText();
            try {
                encryptionContent = Algoritmalar.startMessage(algoritma, userInputEncryptMessage, userInputEncryptKey, "Şifrele", "Şifrele", "Şifrele");
            } catch (Exception error) {
                showErrorMessage("Şifrelemek İstediğiniz Metin Çok Büyük ya da Girilen Genel Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }
            String[] encryptInfoContent = encryptionContent.split("\n");

            if (encryptionContent.equals("Giriş Yapılmadı.")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Metni ve Genel Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForAsymmetricButtonEncrypt.setDisable(false);
                processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
                encryptMessageForAsymmetric.setEditable(true);
                encryptKeyForAsymmetric.setEditable(true);
                copyEncryptedMessageButtonForAsymmetric.setVisible(false);
            }

            else {
                encryptedMessageInfo = new Label(encryptInfoContent[0]);
                String[] parts1 = encryptedMessageInfo.getText().split("! ");
                Label encryptedMessageInfoLabel = new Label(parts1[0] + "!");
                thirdGridAsymmetric = new GridPane();
                thirdGridAsymmetric.add(encryptedMessageInfoLabel, 0, 0);
                thirdGridAsymmetric.add(copyEncryptedMessageButtonForAsymmetric, 1, 0);
                thirdGridAsymmetric.setHgap(5);
                processMenuForAsymmetric.getChildren().add(thirdGridAsymmetric);
                processMenuForAsymmetricButtonEncrypt.setDisable(true);
                processMenuForAsymmetricButtonEncryptActivate.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonFileEncrypt.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
                encryptMessageForAsymmetric.setEditable(false);
                encryptKeyForAsymmetric.setEditable(false);
                copyEncryptedMessageButtonForAsymmetric.setVisible(true);
            }
        });

        processMenuForAsymmetricButtonEncryptActivate.setOnAction(e -> {
            processMenuForAsymmetric.getChildren().removeAll(thirdGridAsymmetric);
            processMenuForAsymmetricButtonEncrypt.setDisable(false);
            processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
            encryptMessageForAsymmetric.setEditable(true);
            encryptKeyForAsymmetric.setEditable(true);
            copyEncryptedMessageButtonForAsymmetric.setVisible(false);
        });

        processMenuForAsymmetricButtonFileEncrypt.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytes;
                try {
                    fileBytes = Files.readAllBytes(selectedFile.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                String[] fileFormat = selectedFileName.split("\\.");
                byte[] fileFormatBytes;
                try {
                    fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
                } catch (UnsupportedEncodingException ee) {
                    throw new RuntimeException(ee);
                }

                byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
                byte[] fileBytesAll = new byte[fileBytes.length+9+fileFormatBytes.length];
                System.arraycopy(fileBytes, 0, fileBytesAll, 0, fileBytes.length);
                System.arraycopy(numbers, 0, fileBytesAll, fileBytes.length, 9);
                System.arraycopy(fileFormatBytes, 0, fileBytesAll, fileBytes.length+9, fileFormatBytes.length);


                String userInputKey = encryptKeyForAsymmetric.getText();

                try {
                    encryptionContentBytes = Algoritmalar.startFile(algoritma, fileBytesAll, userInputKey, null, null, "Şifrele");
                } catch (Exception error) {
                    showErrorMessage("Girilen Dosya ya da Anahtar Hatalıdır.");
                    throw new RuntimeException(error);
                }

                if (bytesToHex(encryptionContentBytes).equals("31")) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Dosya Şifrelenemiyor");
                    alertEntering.setContentText("Girilen Dosya Çok Büyük");
                    alertEntering.showAndWait();
                    throw new RuntimeException("Girilen Dosya Çok Büyük");
                }

                if (encryptionContentBytes == null) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Giriş Yapılmadı");
                    alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                    alertEntering.showAndWait();
                    processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
                    processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(false);
                    processMenuForAsymmetricButtonEncrypt.setDisable(true);
                    processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
                    processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
                    processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
                    encryptMessageForAsymmetric.setEditable(true);
                    encryptKeyForAsymmetric.setEditable(true);
                    saveEncryptFileButtonForAsymmetric.setVisible(false);
                }

                else {
                    String keyAndFormat = bytesToHex(encryptionContentBytes);
                    String[] parts = keyAndFormat.split("012345677654321031");
                    publicKeyInfoBytes = hexToBytes(parts[0]);
                    publicKeyfileFormatBytes = hexToBytes(parts[1]);

                    Label encryptInfoLabel = new Label("Dosya şifrelendi!");
                    thirdGridAsymmetric = new GridPane();
                    thirdGridAsymmetric.add(encryptInfoLabel, 0, 0);
                    thirdGridAsymmetric.add(saveEncryptFileButtonForAsymmetric, 1, 0);
                    thirdGridAsymmetric.setHgap(5);
                    processMenuForAsymmetric.getChildren().add(thirdGridAsymmetric);
                    processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
                    processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
                    processMenuForAsymmetricButtonEncrypt.setDisable(true);
                    processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
                    processMenuForAsymmetricButtonFileEncrypt.setDisable(true);
                    processMenuForAsymmetricButtonFileEncryptActivate.setDisable(false);
                    encryptMessageForAsymmetric.setEditable(false);
                    encryptKeyForAsymmetric.setEditable(false);
                    copyDecryptKeyFileButtonForAsymmetric.setVisible(true);
                    saveEncryptFileButtonForAsymmetric.setVisible(true);
                }
            }
            else {
                processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(false);
                processMenuForAsymmetricButtonEncrypt.setDisable(false);
                processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
                processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
                encryptMessageForAsymmetric.setEditable(true);
                encryptKeyForAsymmetric.setEditable(true);
                saveEncryptFileButtonForAsymmetric.setVisible(false);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForAsymmetricButtonFileEncryptActivate.setOnAction(e -> {
            processMenuForAsymmetric.getChildren().removeAll(thirdGridAsymmetric);
            processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonEncrypt.setDisable(false);
            processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
            encryptMessageForAsymmetric.setEditable(true);
            encryptKeyForAsymmetric.setEditable(true);
            copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
            saveEncryptFileButtonForAsymmetric.setVisible(false);
        });

        processMenuForAsymmetricButtonFileDecryptEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageDecryptionAsymmetric = decryptMessageForAsymmetric.getText();
            if (selectedFile != null) {
                processMenuForAsymmetricButtonFileDecryptEnter.setDisable(true);
                processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(false);
                processMenuForAsymmetricButtonDecrypt.setDisable(true);
                processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
                processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
                processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
                decryptMessageForAsymmetric.setEditable(false);
                decryptKeyForAsymmetric.setEditable(true);
                decryptMessageForAsymmetric.clear();
                selectedFileName = selectedFile.getName();
                decryptMessageForAsymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
                processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonDecrypt.setDisable(false);
                processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
                processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
                processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
                decryptMessageForAsymmetric.setEditable(true);
                decryptKeyForAsymmetric.setEditable(true);
                decryptMessageForAsymmetric.clear();
                decryptMessageForAsymmetric.appendText(wrotedMessageDecryptionAsymmetric);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForAsymmetricButtonFileDecryptEnterActivate.setOnAction(e -> {
            processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonDecrypt.setDisable(false);
            processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
            decryptMessageForAsymmetric.setEditable(true);
            decryptKeyForAsymmetric.setEditable(true);
            decryptMessageForAsymmetric.clear();
            decryptMessageForAsymmetric.appendText(wrotedMessageDecryptionAsymmetric);
        });

        processMenuForAsymmetricButtonDecrypt.setOnAction(e -> {
            String userInputDecryptMessage = decryptMessageForAsymmetric.getText();
            String userInputDecryptKey = decryptKeyForAsymmetric.getText();
            try {
                decryptinContent = Algoritmalar.startMessage(algoritma, "Çöz", "Çöz", userInputDecryptMessage, "Çöz", userInputDecryptKey);
            } catch (Exception error) {
                showErrorMessage("Girilen Şifreli Metin ya da Özel Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (decryptinContent.equals("Giriş Yapılmadı.")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Metni ve Özel Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForAsymmetricButtonDecrypt.setDisable(false);
                processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
                decryptMessageForAsymmetric.setEditable(true);
                decryptKeyForAsymmetric.setEditable(true);
                copyDecryptedMessageButtonForAsymmetric.setVisible(false);
            }

            else {
                decryptionInfo = new Label(decryptinContent);
                String[] parts1 = decryptionInfo.getText().split("! ");
                Label decryptionInfoLabel = new Label(parts1[0] + "!");
                fourthGridAsymmetric = new GridPane();
                fourthGridAsymmetric.add(decryptionInfoLabel, 0, 0);
                fourthGridAsymmetric.add(copyDecryptedMessageButtonForAsymmetric, 1, 0);
                fourthGridAsymmetric.setHgap(5);
                processMenuForAsymmetric.getChildren().add(fourthGridAsymmetric);
                processMenuForAsymmetricButtonDecrypt.setDisable(true);
                processMenuForAsymmetricButtonDecryptActivate.setDisable(false);
                decryptMessageForAsymmetric.setEditable(false);
                decryptKeyForAsymmetric.setEditable(false);
                copyDecryptedMessageButtonForAsymmetric.setVisible(true);
            }
        });

        processMenuForAsymmetricButtonDecryptActivate.setOnAction(e -> {
            processMenuForAsymmetric.getChildren().removeAll(fourthGridAsymmetric);
            processMenuForAsymmetricButtonDecrypt.setDisable(false);
            processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
            decryptMessageForAsymmetric.setEditable(true);
            decryptKeyForAsymmetric.setEditable(true);
        });

        processMenuForAsymmetricButtonFileDecrypt.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytes;
                try {
                    fileBytes = Files.readAllBytes(selectedFile.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                String userInputDecryptKey = decryptKeyForAsymmetric.getText();

                try {
                    decryptionContentBytes = Algoritmalar.startFile(algoritma, null, "Çöz", fileBytes, null, userInputDecryptKey);
                } catch (Exception error) {
                    showErrorMessage("Girilen Dosya ya da Anahtar Hatalıdır.");
                    throw new RuntimeException(error);
                }

                if (decryptionContentBytes == null) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Giriş Yapılmadı");
                    alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Şifreli Dosyayı ve Anahtarı Girin");
                    alertEntering.showAndWait();
                    processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
                    processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
                    processMenuForAsymmetricButtonDecrypt.setDisable(true);
                    processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
                    processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
                    processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
                    decryptMessageForAsymmetric.setEditable(true);
                    decryptKeyForAsymmetric.setEditable(true);
                    saveDecryptFileButtonForAsymmetric.setVisible(false);
                }

                else {
                    Label decryptInfoLabel = new Label("Dosya çözüldü!");
                    thirdGridAsymmetric = new GridPane();
                    thirdGridAsymmetric.add(decryptInfoLabel, 0, 1);
                    thirdGridAsymmetric.add(saveDecryptFileButtonForAsymmetric, 1, 1);
                    thirdGridAsymmetric.setHgap(5);
                    processMenuForAsymmetric.getChildren().add(thirdGridAsymmetric);
                    processMenuForAsymmetricButtonFileDecryptEnter.setDisable(true);
                    processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
                    processMenuForAsymmetricButtonDecrypt.setDisable(true);
                    processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
                    processMenuForAsymmetricButtonFileDecrypt.setDisable(true);
                    processMenuForAsymmetricButtonFileDecryptActivate.setDisable(false);
                    decryptMessageForAsymmetric.setEditable(false);
                    decryptKeyForAsymmetric.setEditable(false);
                    saveDecryptFileButtonForAsymmetric.setVisible(true);
                }
            }
            else {
                processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
                processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonDecrypt.setDisable(false);
                processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
                processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
                processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
                decryptMessageForAsymmetric.setEditable(true);
                decryptKeyForAsymmetric.setEditable(true);
                saveDecryptFileButtonForAsymmetric.setVisible(false);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForAsymmetricButtonFileDecryptActivate.setOnAction(e -> {
            processMenuForAsymmetric.getChildren().removeAll(thirdGridAsymmetric);
            processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonDecrypt.setDisable(false);
            processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
            processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
            decryptMessageForAsymmetric.setEditable(true);
            decryptKeyForAsymmetric.setEditable(true);
            saveDecryptFileButtonForAsymmetric.setVisible(false);
        });

        copyEncryptKeyButtonForAsymmetric.setOnAction(e -> {
            String[] encryptKey = encryptKeyInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(encryptKey[1]);
            clipboard.setContent(content);

            Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            encryptKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
            encryptKeyCopy.showAndWait();
        });

        copyEncryptKeyFileButtonForAsymmetric.setOnAction(e -> {
            String encryptKey = bytesToHex(encryptKeyInfoBytes);
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(encryptKey);
            clipboard.setContent(content);

            Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            encryptKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
            encryptKeyCopy.showAndWait();
        });

        copyDecryptKeyButtonForAsymmetric.setOnAction(e -> {
            String[] decryptKey = decryptKeyInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(decryptKey[1]);
            clipboard.setContent(content);

            Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            encryptKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
            encryptKeyCopy.showAndWait();
        });

        copyDecryptKeyFileButtonForAsymmetric.setOnAction(e -> {
            String decryptKey = bytesToHex(decryptKeyInfoBytes);
            String fileFormat = bytesToHex(publicKeyfileFormatBytes);
            String decryptKeyAndFormat = decryptKey + ":" + fileFormat;

            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(decryptKeyAndFormat);
            clipboard.setContent(content);

            Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            encryptKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
            encryptKeyCopy.showAndWait();
        });

        copyEncryptedMessageButtonForAsymmetric.setOnAction(e -> {
            String[] message = encryptedMessageInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(message[1]);
            clipboard.setContent(content);

            Alert messageEncrypted = new Alert(Alert.AlertType.INFORMATION);
            messageEncrypted.setHeaderText("Şifreli Mesaj Kopyalandı");
            messageEncrypted.showAndWait();
        });

        saveEncryptFileButtonForAsymmetric.setOnAction(e -> {
            byte[] bytes = publicKeyInfoBytes;
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
        });

        copyDecryptedMessageButtonForAsymmetric.setOnAction(e -> {
            String[] message = decryptionInfo.getText().split("Şifresi çözülmüş metin oluşturuldu! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(message[1]);
            clipboard.setContent(content);

            Alert messageDecryption = new Alert(Alert.AlertType.INFORMATION);
            messageDecryption.setHeaderText("Şifresi Çözülmüş Mesaj Kopyalandı");
            messageDecryption.showAndWait();
        });

        saveDecryptFileButtonForAsymmetric.setOnAction(e -> {
            String separate = bytesToHex(decryptionContentBytes);
            String[] parts = separate.split("012345677654321031");

            byte[] keyInfoBytes = hexToBytes(parts[0]);
            byte[] fileFormatBytes = hexToBytes(parts[1]);

            byte[] bytes = keyInfoBytes;
            byte[] fileNameFormatBytes = fileFormatBytes;
            String fileNameFormat = new String(fileNameFormatBytes, StandardCharsets.UTF_8);

            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Çözülmüş Dosyayı Kaydet");
            fileChooser.setInitialFileName("cozulmus_dosya");
            FileChooser.ExtensionFilter fileFormat = new FileChooser.ExtensionFilter("Şifrelenmiş Dosyalar", "*." + fileNameFormat);
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
        });










        processMenuForSignButtonBack.setOnAction(e -> {
            processMenuForSignButtonGenerateKeys.setDisable(false);
            processMenuForSignButtonGenerateKeysActivate.setDisable(true);
            processMenuForSignButtonGenerateKeysFile.setDisable(false);
            processMenuForSignButtonGenerateKeysFileActivate.setDisable(true);
            processMenuForSignButtonFileSignEnter.setDisable(false);
            processMenuForSignButtonFileSignEnterActivate.setDisable(true);
            processMenuForSignButtonSign.setDisable(false);
            processMenuForSignButtonSignActivate.setDisable(true);
            processMenuForSignButtonFileSign.setDisable(false);
            processMenuForSignButtonFileSignActivate.setDisable(true);
            processMenuForSignButtonFileValidateEnter.setDisable(false);
            processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
            processMenuForSignButtonFileSignedEnter.setDisable(false);
            processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
            processMenuForSignButtonValidate.setDisable(false);
            processMenuForSignButtonValidateActivate.setDisable(true);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            signMessageForSign.clear();
            signMessageForSign.setEditable(true);
            signKeyForSign.clear();
            signKeyForSign.setEditable(true);
            validateMessageForSign.clear();
            validateMessageForSign.setEditable(true);
            validateSignatureForSign.clear();
            validateSignatureForSign.setEditable(true);
            validateKeyForSign.clear();
            validateKeyForSign.setEditable(true);
            copySignKeyButtonForSign.setVisible(false);
            copySignKeyFileButtonForSign.setVisible(false);
            copyValidateKeyButtonForSign.setVisible(false);
            copyValidateKeyFileButtonForSign.setVisible(false);
            copySignedMessageButtonForSign.setVisible(false);
            saveSignedFileButtonForSign.setVisible(false);
            processMenuForSign.getChildren().clear();
            stage.getScene().setRoot(mainMenu);
        });

        processMenuForSignButtonGenerateKeys.setOnAction(e -> {
            try {
                keysContent = Algoritmalar.startMessage(algoritma, "Anahtar", "Anahtar", "Anahtar", "Anahtar", "Anahtar");
            } catch (Exception error) {
                throw new RuntimeException(error);
            }
            String[] keysInfoContent = keysContent.split("\n");


            signKeyInfo = new Label(keysInfoContent[0]);
            String[] parts1 = signKeyInfo.getText().split("! ");
            Label signKeyInfoLabel = new Label(parts1[0] + "!");
            firstGridSign = new GridPane();
            firstGridSign.add(signKeyInfoLabel, 0, 0);
            firstGridSign.add(copySignKeyButtonForSign, 1, 0);
            firstGridSign.setHgap(5);
            validateKeyInfo = new Label(keysInfoContent[1]);
            String[] parts2 = validateKeyInfo.getText().split("! ");
            Label validateKeyInfoLabel = new Label(parts2[0] + "!");
            secondGridSign = new GridPane();
            secondGridSign.add(validateKeyInfoLabel, 0, 0);
            secondGridSign.add(copyValidateKeyButtonForSign, 1, 0);
            secondGridSign.setHgap(5);
            processMenuForSign.getChildren().addAll(firstGridSign, secondGridSign);
            processMenuForSignButtonGenerateKeys.setDisable(true);
            processMenuForSignButtonGenerateKeysActivate.setDisable(false);
            copySignKeyButtonForSign.setVisible(true);
            copyValidateKeyButtonForSign.setVisible(true);
        });

        processMenuForSignButtonGenerateKeysActivate.setOnAction(e -> {
            processMenuForSign.getChildren().removeAll(firstGridSign, secondGridSign);
            processMenuForSignButtonGenerateKeys.setDisable(false);
            processMenuForSignButtonGenerateKeysActivate.setDisable(true);
            copySignKeyButtonForSign.setVisible(false);
            copyValidateKeyButtonForSign.setVisible(false);
        });

        processMenuForSignButtonGenerateKeysFile.setOnAction(e -> {
            try {
                keysContentBytes = Algoritmalar.startFile(algoritma, null, "Anahtar", null, null, "Anahtar");
            } catch (Exception error) {
                throw new RuntimeException(error);
            }
            String keysInfoContent = bytesToHex(keysContentBytes);
            String[] partsPublicAndPrivate = keysInfoContent.split("012345677654321031012345677654321031");


            signKeyInfoBytes = hexToBytes(partsPublicAndPrivate[0]);
            Label signKeyInfoLabel = new Label("Özel anahtar oluşturuldu!");
            firstGridSign = new GridPane();
            firstGridSign.add(signKeyInfoLabel, 0, 0);
            firstGridSign.add(copySignKeyFileButtonForSign, 1, 0);
            firstGridSign.setHgap(5);
            validateKeyInfoBytes = hexToBytes(partsPublicAndPrivate[1]);
            Label validateKeyInfoLabel = new Label("Genel anahtar oluşturuldu!");
            secondGridSign = new GridPane();
            secondGridSign.add(validateKeyInfoLabel, 0, 0);
            secondGridSign.add(copyValidateKeyFileButtonForSign, 1, 0);
            secondGridSign.setHgap(5);
            processMenuForSign.getChildren().addAll(firstGridSign, secondGridSign);
            processMenuForSignButtonGenerateKeys.setDisable(true);
            processMenuForSignButtonGenerateKeysActivate.setDisable(true);
            processMenuForSignButtonGenerateKeysFile.setDisable(true);
            processMenuForSignButtonGenerateKeysFileActivate.setDisable(false);
            copySignKeyFileButtonForSign.setVisible(true);
            copyValidateKeyFileButtonForSign.setVisible(false);
        });

        processMenuForSignButtonGenerateKeysFileActivate.setOnAction(e -> {
            processMenuForSign.getChildren().removeAll(firstGridSign, secondGridSign);
            processMenuForSignButtonGenerateKeys.setDisable(false);
            processMenuForSignButtonGenerateKeysActivate.setDisable(true);
            processMenuForSignButtonGenerateKeysFile.setDisable(false);
            processMenuForSignButtonGenerateKeysFileActivate.setDisable(true);
            copySignKeyFileButtonForSign.setVisible(false);
            copyValidateKeyFileButtonForSign.setVisible(false);
        });

        processMenuForSignButtonFileSignEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageSigning = signMessageForSign.getText();
            if (selectedFile != null) {
                processMenuForSignButtonFileSignEnter.setDisable(true);
                processMenuForSignButtonFileSignEnterActivate.setDisable(false);
                processMenuForSignButtonSign.setDisable(true);
                processMenuForSignButtonSignActivate.setDisable(true);
                processMenuForSignButtonFileSign.setDisable(false);
                processMenuForSignButtonFileSignActivate.setDisable(true);
                signMessageForSign.setEditable(false);
                signKeyForSign.setEditable(true);
                signMessageForSign.clear();
                selectedFileName = selectedFile.getName();
                signMessageForSign.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForSignButtonFileSignEnter.setDisable(false);
                processMenuForSignButtonFileSignEnterActivate.setDisable(true);
                processMenuForSignButtonSign.setDisable(false);
                processMenuForSignButtonSignActivate.setDisable(true);
                processMenuForSignButtonFileSign.setDisable(false);
                processMenuForSignButtonFileSignActivate.setDisable(true);
                signMessageForSign.setEditable(true);
                signKeyForSign.setEditable(true);
                signMessageForSign.clear();
                signMessageForSign.appendText(wrotedMessageSigning);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSignButtonFileSignEnterActivate.setOnAction(e -> {
            processMenuForSignButtonFileSignEnter.setDisable(false);
            processMenuForSignButtonFileSignEnterActivate.setDisable(true);
            processMenuForSignButtonSign.setDisable(false);
            processMenuForSignButtonSignActivate.setDisable(true);
            processMenuForSignButtonFileSign.setDisable(false);
            processMenuForSignButtonFileSignActivate.setDisable(true);
            signMessageForSign.setEditable(true);
            signKeyForSign.setEditable(true);
            signMessageForSign.clear();
            signMessageForSign.appendText(wrotedMessageSigning);
        });

        processMenuForSignButtonSign.setOnAction(e -> {
            String userInputSignMessage = signMessageForSign.getText();
            String userInputSignKey = signKeyForSign.getText();
            try {
                signContent = Algoritmalar.startMessage(algoritma, userInputSignMessage, userInputSignKey, "İmzala", "İmzala", "İmzala");
            } catch (Exception error) {
                showErrorMessage("Girilen Özel Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }
            String[] signInfoContent = signContent.split("\n");

            if (signContent.equals("Giriş Yapılmadı.")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen İmzalanmasını İstediğiniz Metni ve Özel Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForSignButtonSign.setDisable(false);
                processMenuForSignButtonSignActivate.setDisable(true);
                signMessageForSign.setEditable(true);
                signKeyForSign.setEditable(true);
                copySignedMessageButtonForSign.setVisible(false);
            }

            else {
                signedMessageInfo = new Label(signInfoContent[0]);
                String[] parts1 = signedMessageInfo.getText().split("! ");
                Label signedMessageInfoLabel = new Label(parts1[0] + "!");
                thirdGridSign = new GridPane();
                thirdGridSign.add(signedMessageInfoLabel, 0, 0);
                thirdGridSign.add(copySignedMessageButtonForSign, 1, 0);
                thirdGridSign.setHgap(5);
                processMenuForSign.getChildren().add(thirdGridSign);
                processMenuForSignButtonSign.setDisable(true);
                processMenuForSignButtonSignActivate.setDisable(false);
                signMessageForSign.setEditable(false);
                signKeyForSign.setEditable(false);
                copySignedMessageButtonForSign.setVisible(true);
            }
        });

        processMenuForSignButtonSignActivate.setOnAction(e -> {
            processMenuForSign.getChildren().removeAll(thirdGridSign);
            processMenuForSignButtonSign.setDisable(false);
            processMenuForSignButtonSignActivate.setDisable(true);
            signMessageForSign.setEditable(true);
            signKeyForSign.setEditable(true);
            copySignedMessageButtonForSign.setVisible(false);
        });

        processMenuForSignButtonFileSign.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytes;
                try {
                    fileBytes = Files.readAllBytes(selectedFile.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                String[] fileFormat = selectedFileName.split("\\.");
                byte[] fileFormatBytes;
                try {
                    fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
                } catch (UnsupportedEncodingException ee) {
                    throw new RuntimeException(ee);
                }

                byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
                byte[] fileBytesAll = new byte[fileBytes.length+9+fileFormatBytes.length];
                System.arraycopy(fileBytes, 0, fileBytesAll, 0, fileBytes.length);
                System.arraycopy(numbers, 0, fileBytesAll, fileBytes.length, 9);
                System.arraycopy(fileFormatBytes, 0, fileBytesAll, fileBytes.length+9, fileFormatBytes.length);


                String userInputSignKey = signKeyForSign.getText();

                try {
                    signContentBytes = Algoritmalar.startFile(algoritma, fileBytesAll, userInputSignKey, null, null, "İmzala");
                } catch (Exception error) {
                    showErrorMessage("Girilen Dosya ya da Anahtar Hatalıdır.");
                    throw new RuntimeException(error);
                }

                if (bytesToHex(signContentBytes).equals("31")) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Dosya Şifrelenemiyor");
                    alertEntering.setContentText("Girilen Dosya Çok Büyük");
                    alertEntering.showAndWait();
                    throw new RuntimeException("Girilen Dosya Çok Büyük");
                }

                if (signContentBytes == null) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Giriş Yapılmadı");
                    alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                    alertEntering.showAndWait();
                    processMenuForSignButtonFileSignEnter.setDisable(true);
                    processMenuForSignButtonFileSignEnterActivate.setDisable(false);
                    processMenuForSignButtonSign.setDisable(true);
                    processMenuForSignButtonSignActivate.setDisable(true);
                    processMenuForSignButtonFileSign.setDisable(false);
                    processMenuForSignButtonFileSignActivate.setDisable(true);
                    signMessageForSign.setEditable(true);
                    signKeyForSign.setEditable(true);
                    saveSignedFileButtonForSign.setVisible(false);
                }

                else {
                    String keyAndFormat = bytesToHex(signContentBytes);
                    String[] parts = keyAndFormat.split("012345677654321031");
                    privateKeyInfoBytes = hexToBytes(parts[0]);
                    privateKeyfileFormatBytes = hexToBytes(parts[1]);

                    Label signInfoLabel = new Label("Dosya İmzalandı!");
                    fourthGridSign = new GridPane();
                    fourthGridSign.add(signInfoLabel, 0, 0);
                    fourthGridSign.add(saveSignedFileButtonForSign, 1, 0);
                    fourthGridSign.setHgap(5);
                    processMenuForSign.getChildren().addAll(fourthGridSign);
                    processMenuForSignButtonFileSignEnter.setDisable(true);
                    processMenuForSignButtonFileSignEnterActivate.setDisable(true);
                    processMenuForSignButtonSign.setDisable(true);
                    processMenuForSignButtonSignActivate.setDisable(true);
                    processMenuForSignButtonFileSign.setDisable(true);
                    processMenuForSignButtonFileSignActivate.setDisable(false);
                    signMessageForSign.setEditable(false);
                    signKeyForSign.setEditable(false);
                    copyValidateKeyFileButtonForSign.setVisible(true);
                    saveSignedFileButtonForSign.setVisible(true);
                }
            }
            else {
                processMenuForSignButtonFileSignEnter.setDisable(true);
                processMenuForSignButtonFileSignEnterActivate.setDisable(false);
                processMenuForSignButtonSign.setDisable(false);
                processMenuForSignButtonSignActivate.setDisable(true);
                processMenuForSignButtonFileSign.setDisable(false);
                processMenuForSignButtonFileSignActivate.setDisable(true);
                signMessageForSign.setEditable(true);
                signKeyForSign.setEditable(true);
                saveSignedFileButtonForSign.setVisible(false);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSignButtonFileSignActivate.setOnAction(e -> {
            processMenuForSign.getChildren().removeAll(fourthGridSign);
            processMenuForSignButtonFileSignEnter.setDisable(false);
            processMenuForSignButtonFileSignEnterActivate.setDisable(true);
            processMenuForSignButtonSign.setDisable(false);
            processMenuForSignButtonSignActivate.setDisable(true);
            processMenuForSignButtonFileSign.setDisable(false);
            processMenuForSignButtonFileSignActivate.setDisable(true);
            signMessageForSign.setEditable(true);
            signKeyForSign.setEditable(true);
            copyValidateKeyFileButtonForSign.setVisible(false);
            saveSignedFileButtonForSign.setVisible(false);
        });

        processMenuForSignButtonFileValidateEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageValidating = validateMessageForSign.getText();
            if (selectedFile != null) {
                processMenuForSignButtonFileValidateEnter.setDisable(true);
                processMenuForSignButtonFileValidateEnterActivate.setDisable(false);
                processMenuForSignButtonValidate.setDisable(true);
                processMenuForSignButtonValidateActivate.setDisable(true);
                processMenuForSignButtonFileValidate.setDisable(false);
                processMenuForSignButtonFileValidateActivate.setDisable(true);
                validateMessageForSign.setEditable(false);
                validateSignatureForSign.setEditable(false);
                validateMessageForSign.clear();
                selectedFileName = selectedFile.getName();
                validateMessageForSign.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForSignButtonFileValidateEnter.setDisable(false);
                processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
                processMenuForSignButtonValidate.setDisable(false);
                processMenuForSignButtonValidateActivate.setDisable(true);
                processMenuForSignButtonFileValidate.setDisable(false);
                processMenuForSignButtonFileValidateActivate.setDisable(true);
                validateMessageForSign.setEditable(true);
                validateSignatureForSign.setEditable(true);
                validateMessageForSign.clear();
                validateMessageForSign.appendText(wrotedMessageValidating);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSignButtonFileValidateEnterActivate.setOnAction(e -> {
            processMenuForSignButtonFileValidateEnter.setDisable(false);
            processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
            processMenuForSignButtonValidate.setDisable(false);
            processMenuForSignButtonValidateActivate.setDisable(true);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            validateMessageForSign.setEditable(true);
            validateSignatureForSign.setEditable(true);
            validateMessageForSign.clear();
            validateMessageForSign.appendText(wrotedMessageValidating);
        });

        processMenuForSignButtonFileSignedEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFileAlternative = fileChooser.showOpenDialog(stage);
            wrotedSignedMessage = validateSignatureForSign.getText();
            if (selectedFileAlternative != null) {
                processMenuForSignButtonFileSignedEnter.setDisable(true);
                processMenuForSignButtonFileSignedEnterActivate.setDisable(false);
                processMenuForSignButtonValidate.setDisable(true);
                processMenuForSignButtonValidateActivate.setDisable(true);
                processMenuForSignButtonFileValidate.setDisable(false);
                processMenuForSignButtonFileValidateActivate.setDisable(true);
                validateMessageForSign.setEditable(false);
                validateSignatureForSign.setEditable(false);
                validateSignatureForSign.clear();
                selectedFileAlternativeName = selectedFileAlternative.getName();
                validateSignatureForSign.appendText("Seçtiğiniz Dosya:\n" + selectedFileAlternativeName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileAlternativeName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForSignButtonFileSignedEnter.setDisable(false);
                processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
                processMenuForSignButtonValidate.setDisable(false);
                processMenuForSignButtonValidateActivate.setDisable(true);
                processMenuForSignButtonFileValidate.setDisable(false);
                processMenuForSignButtonFileValidateActivate.setDisable(true);
                validateMessageForSign.setEditable(true);
                validateSignatureForSign.setEditable(true);
                validateSignatureForSign.clear();
                validateSignatureForSign.appendText(wrotedSignedMessage);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForSignButtonFileSignedEnterActivate.setOnAction(e -> {
            processMenuForSignButtonFileSignedEnter.setDisable(false);
            processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
            processMenuForSignButtonValidate.setDisable(false);
            processMenuForSignButtonValidateActivate.setDisable(true);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            validateMessageForSign.setEditable(true);
            validateSignatureForSign.setEditable(true);
            validateSignatureForSign.clear();
            validateSignatureForSign.appendText(wrotedSignedMessage);
        });

        processMenuForSignButtonValidate.setOnAction(e -> {
            String userInputValidateMessage = validateMessageForSign.getText();
            String userInputSignature = validateSignatureForSign.getText();
            String userInputValidateKey = validateKeyForSign.getText();
            try {
                validateContent = Algoritmalar.startMessage(algoritma, "Doğrula", "Doğrula", userInputValidateMessage, userInputSignature, userInputValidateKey);
            } catch (Exception error) {
                showErrorMessage("Girilen Genel Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (validateContent.equals("Giriş Yapılmadı.")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Doğrulamak İstediğiniz Metni ve Genel Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForSignButtonValidate.setDisable(false);
                processMenuForSignButtonValidateActivate.setDisable(true);
                validateMessageForSign.setEditable(true);
                validateSignatureForSign.setEditable(true);
                validateKeyForSign.setEditable(true);
            }

            else {
                if (validateContent.equals("Doğrulama Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)")) {
                    Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                    alertEntering.setHeaderText("Dikkat");
                    alertEntering.setContentText("Doğrulama Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                    alertEntering.showAndWait();
                    processMenuForSignButtonValidate.setDisable(true);
                    processMenuForSignButtonValidateActivate.setDisable(false);
                    validateMessageForSign.setEditable(false);
                    validateSignatureForSign.setEditable(false);
                    validateKeyForSign.setEditable(false);
                }
                if (validateContent.equals("Doğrulama Gerçekleşti. (Elinizdeki Orijinal Metin.)")) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Sorun Yok");
                    alertEntering.setContentText("Doğrulama Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                    alertEntering.showAndWait();
                    processMenuForSignButtonValidate.setDisable(true);
                    processMenuForSignButtonValidateActivate.setDisable(false);
                    validateMessageForSign.setEditable(false);
                    validateSignatureForSign.setEditable(false);
                    validateKeyForSign.setEditable(false);
                }
            }
        });

        processMenuForSignButtonValidateActivate.setOnAction(e -> {
            processMenuForSignButtonValidate.setDisable(false);
            processMenuForSignButtonValidateActivate.setDisable(true);
            validateMessageForSign.setEditable(true);
            validateSignatureForSign.setEditable(true);
            validateKeyForSign.setEditable(true);
        });

        processMenuForSignButtonFileValidate.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytesValidate;
                try {
                    fileBytesValidate = Files.readAllBytes(selectedFile.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                String[] fileFormat = selectedFileName.split("\\.");
                byte[] fileFormatBytes;
                try {
                    fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
                } catch (UnsupportedEncodingException ee) {
                    throw new RuntimeException(ee);
                }

                byte[] numbers = new byte[]{0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
                byte[] fileBytesValidateFinal = new byte[fileBytesValidate.length + 9 + fileFormatBytes.length];
                System.arraycopy(fileBytesValidate, 0, fileBytesValidateFinal, 0, fileBytesValidate.length);
                System.arraycopy(numbers, 0, fileBytesValidateFinal, fileBytesValidate.length, 9);
                System.arraycopy(fileFormatBytes, 0, fileBytesValidateFinal, fileBytesValidate.length + 9, fileFormatBytes.length);

                byte[] fileBytesSignature;
                try {
                    fileBytesSignature = Files.readAllBytes(selectedFileAlternative.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                String userInputValidateKey = validateKeyForSign.getText();

                try {
                    validateContentBytes = Algoritmalar.startFile(algoritma, null, "Doğrula", fileBytesValidateFinal, fileBytesSignature, userInputValidateKey);
                } catch (Exception error) {
                    showErrorMessage("Girilen Genel Anahtar Hatalıdır.");
                    throw new RuntimeException(error);
                }


                if (validateContentBytes == null) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Giriş Yapılmadı");
                    alertEntering.setContentText("Lütfen Şüphelendiğiniz Metni ve Hashi Girin");
                    alertEntering.showAndWait();
                    processMenuForSignButtonFileValidateEnter.setDisable(false);
                    processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
                    processMenuForSignButtonFileSignedEnter.setDisable(false);
                    processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
                    processMenuForSignButtonValidate.setDisable(true);
                    processMenuForSignButtonValidateActivate.setDisable(true);
                    processMenuForSignButtonFileValidate.setDisable(false);
                    processMenuForSignButtonFileValidateActivate.setDisable(true);
                    validateMessageForSign.setEditable(true);
                    validateSignatureForSign.setEditable(true);
                } else {
                    if (bytesToHex(validateContentBytes).equals("3131")) {
                        Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                        alertEntering.setHeaderText("Dikkat");
                        alertEntering.setContentText("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                        alertEntering.showAndWait();
                        processMenuForSignButtonFileValidateEnter.setDisable(true);
                        processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
                        processMenuForSignButtonFileSignedEnter.setDisable(true);
                        processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
                        processMenuForSignButtonValidate.setDisable(true);
                        processMenuForSignButtonValidateActivate.setDisable(true);
                        processMenuForSignButtonFileValidate.setDisable(true);
                        processMenuForSignButtonFileValidateActivate.setDisable(false);
                        validateMessageForSign.setEditable(false);
                        validateSignatureForSign.setEditable(false);
                    }
                    if (bytesToHex(validateContentBytes).equals("31")) {
                        Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                        alertEntering.setHeaderText("Sorun Yok");
                        alertEntering.setContentText("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                        alertEntering.showAndWait();
                        processMenuForSignButtonFileValidateEnter.setDisable(true);
                        processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
                        processMenuForSignButtonFileSignedEnter.setDisable(true);
                        processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
                        processMenuForSignButtonValidate.setDisable(true);
                        processMenuForSignButtonValidateActivate.setDisable(true);
                        processMenuForSignButtonFileValidate.setDisable(true);
                        processMenuForSignButtonFileValidateActivate.setDisable(false);
                        validateMessageForSign.setEditable(false);
                        validateSignatureForSign.setEditable(false);
                    }
                }
            }
        });

        processMenuForSignButtonFileValidateActivate.setOnAction(e -> {
            processMenuForSignButtonFileValidateEnter.setDisable(false);
            processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
            processMenuForSignButtonFileSignedEnter.setDisable(false);
            processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
            processMenuForSignButtonValidate.setDisable(false);
            processMenuForSignButtonValidateActivate.setDisable(true);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            validateMessageForSign.setEditable(true);
            validateSignatureForSign.setEditable(true);
        });

        copySignKeyButtonForSign.setOnAction(e -> {
            String[] signKey = signKeyInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(signKey[1]);
            clipboard.setContent(content);

            Alert signKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            signKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
            signKeyCopy.showAndWait();
        });

        copySignKeyFileButtonForSign.setOnAction(e -> {
            String signKey = bytesToHex(signKeyInfoBytes);
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(signKey);
            clipboard.setContent(content);

            Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            encryptKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
            encryptKeyCopy.showAndWait();
        });

        copyValidateKeyButtonForSign.setOnAction(e -> {
            String[] validateKey = validateKeyInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(validateKey[1]);
            clipboard.setContent(content);

            Alert validateKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            validateKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
            validateKeyCopy.showAndWait();
        });

        copyValidateKeyFileButtonForSign.setOnAction(e -> {
            String validateKey = bytesToHex(validateKeyInfoBytes);
            String fileFormat = bytesToHex(privateKeyfileFormatBytes);
            String decryptKeyAndFormat = validateKey + ":" + fileFormat;

            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(decryptKeyAndFormat);
            clipboard.setContent(content);

            Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
            encryptKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
            encryptKeyCopy.showAndWait();
        });

        copySignedMessageButtonForSign.setOnAction(e -> {
            String[] signed = signedMessageInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(signed[1]);
            clipboard.setContent(content);

            Alert signedCopy = new Alert(Alert.AlertType.INFORMATION);
            signedCopy.setHeaderText("İmzalanmış Metin Kopyalandı");
            signedCopy.showAndWait();
        });

        saveSignedFileButtonForSign.setOnAction(e -> {
            byte[] bytes = privateKeyInfoBytes;
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Oluşturulan İmzalı Dosyayı Kaydet");
            fileChooser.setInitialFileName("imzali_dosya");
            FileChooser.ExtensionFilter fileFormat = new FileChooser.ExtensionFilter("İmzalanmış Dosyalar", "*.sig");
            fileChooser.getExtensionFilters().add(fileFormat);
            fileChooser.getSelectedExtensionFilter();
            File file = fileChooser.showSaveDialog(stage);
            try {
                Files.write(file.toPath(), bytes);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
            messageEncrypt.setHeaderText("İmzalı Dosya Kaydedildi");
            messageEncrypt.showAndWait();
        });










        processMenuForHashButtonBack.setOnAction(e -> {
            processMenuForHashButtonFileHashEnter.setDisable(false);
            processMenuForHashButtonFileHashEnterActivate.setDisable(true);
            processMenuForHashButtonHash.setDisable(false);
            processMenuForHashButtonHashActivate.setDisable(true);
            processMenuForHashButtonFileHash.setDisable(false);
            processMenuForHashButtonFileHashActivate.setDisable(true);
            processMenuForHashButtonFileMatchEnter.setDisable(false);
            processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
            processMenuForHashButtonMatch.setDisable(false);
            processMenuForHashButtonMatchActivate.setDisable(true);
            processMenuForHashButtonFileMatch.setDisable(false);
            processMenuForHashButtonFileMatchActivate.setDisable(true);
            hashMessageForHash.clear();
            hashMessageForHash.setEditable(true);
            matchMessageForHash.clear();
            matchMessageForHash.setEditable(true);
            hashForHash.clear();
            hashForHash.setEditable(true);
            copyHashButtonForHash.setVisible(false);
            copyHashFileButtonForHash.setVisible(false);
            processMenuForHash.getChildren().clear();
            selectedFile = null;
            stage.getScene().setRoot(mainMenu);
        });

        processMenuForHashButtonFileHashEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageHashing = hashMessageForHash.getText();
            if (selectedFile != null) {
                processMenuForHashButtonFileHashEnter.setDisable(true);
                processMenuForHashButtonFileHashEnterActivate.setDisable(false);
                processMenuForHashButtonHash.setDisable(true);
                processMenuForHashButtonHashActivate.setDisable(true);
                processMenuForHashButtonFileHash.setDisable(false);
                processMenuForHashButtonFileHashActivate.setDisable(true);
                hashMessageForHash.setEditable(false);
                hashMessageForHash.clear();
                selectedFileName = selectedFile.getName();
                hashMessageForHash.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForHashButtonFileHashEnter.setDisable(false);
                processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                processMenuForHashButtonHash.setDisable(false);
                processMenuForHashButtonHashActivate.setDisable(true);
                processMenuForHashButtonFileHash.setDisable(false);
                processMenuForHashButtonFileHashActivate.setDisable(true);
                hashMessageForHash.setEditable(true);
                hashMessageForHash.clear();
                hashMessageForHash.appendText(wrotedMessageHashing);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForHashButtonFileHashEnterActivate.setOnAction(e -> {
            processMenuForHashButtonFileHashEnter.setDisable(false);
            processMenuForHashButtonFileHashEnterActivate.setDisable(true);
            processMenuForHashButtonHash.setDisable(false);
            processMenuForHashButtonHashActivate.setDisable(true);
            processMenuForHashButtonFileHash.setDisable(false);
            processMenuForHashButtonFileHashActivate.setDisable(true);
            hashMessageForHash.setEditable(true);
            hashMessageForHash.clear();
            hashMessageForHash.appendText(wrotedMessageHashing);
        });

        processMenuForHashButtonHash.setOnAction(e -> {
            String userInputHashMessage = hashMessageForHash.getText();
            try {
                hashContent = Algoritmalar.startMessage(algoritma, userInputHashMessage, "Hasle", "Hashle", "Hashle", "Hashle");
            } catch (Exception error) {
                throw new RuntimeException(error);
            }
            String[] hashInfoContent = hashContent.split("\n");

            if (hashContent.equals("Giriş Yapılmadı.")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Hashlenmesini İstediğiniz Metni Girin");
                alertEntering.showAndWait();
                processMenuForHashButtonFileHashEnter.setDisable(false);
                processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                processMenuForHashButtonHash.setDisable(false);
                processMenuForHashButtonHashActivate.setDisable(true);
                processMenuForHashButtonFileHash.setDisable(false);
                processMenuForHashButtonFileHashActivate.setDisable(true);
                hashMessageForHash.setEditable(true);
                copyHashButtonForHash.setVisible(false);
            }

            else {
                hashInfo = new Label(hashInfoContent[0]);
                String[] parts1 = hashInfo.getText().split("! ");
                Label hashInfoLabel = new Label(parts1[0] + "!");
                firstGridHash = new GridPane();
                firstGridHash.add(hashInfoLabel, 0, 0);
                firstGridHash.add(copyHashButtonForHash, 1, 0);
                firstGridHash.setHgap(5);
                processMenuForHash.getChildren().add(firstGridHash);
                processMenuForHashButtonFileHashEnter.setDisable(true);
                processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                processMenuForHashButtonFileHash.setDisable(true);
                processMenuForHashButtonFileHashActivate.setDisable(true);
                processMenuForHashButtonHash.setDisable(true);
                processMenuForHashButtonHashActivate.setDisable(false);
                hashMessageForHash.setEditable(false);
                copyHashButtonForHash.setVisible(true);
            }
        });

        processMenuForHashButtonHashActivate.setOnAction(e -> {
            processMenuForHash.getChildren().removeAll(firstGridHash);
            processMenuForHashButtonFileHashEnter.setDisable(false);
            processMenuForHashButtonFileHashEnterActivate.setDisable(true);
            processMenuForHashButtonHash.setDisable(false);
            processMenuForHashButtonHashActivate.setDisable(true);
            processMenuForHashButtonFileHash.setDisable(false);
            processMenuForHashButtonFileHashActivate.setDisable(true);
            hashMessageForHash.setEditable(true);
        });

        processMenuForHashButtonFileHash.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytes;
                try {
                    fileBytes = Files.readAllBytes(selectedFile.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                try {
                    hashContentBytes = Algoritmalar.startFile(algoritma, fileBytes, "Hashle", null, null, "Hashle");
                } catch (Exception error) {
                    throw new RuntimeException(error);
                }

                if (hashContentBytes == null) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Giriş Yapılmadı");
                    alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                    alertEntering.showAndWait();
                    processMenuForHashButtonFileHashEnter.setDisable(false);
                    processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                    processMenuForHashButtonHash.setDisable(false);
                    processMenuForHashButtonHashActivate.setDisable(true);
                    processMenuForHashButtonFileHash.setDisable(false);
                    processMenuForHashButtonFileHashActivate.setDisable(true);
                    hashMessageForHash.setEditable(true);
                }

                else {
                    Label encryptMessageInfoLabel = new Label("Dosya şifrelendi!");
                    firstGridHash = new GridPane();
                    firstGridHash.add(encryptMessageInfoLabel, 0, 0);
                    firstGridHash.add(copyHashFileButtonForHash, 1, 0);
                    firstGridHash.setHgap(5);
                    processMenuForHash.getChildren().addAll(firstGridHash);
                    processMenuForHashButtonFileHashEnter.setDisable(true);
                    processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                    processMenuForHashButtonFileHash.setDisable(true);
                    processMenuForHashButtonFileHashActivate.setDisable(false);
                    processMenuForHashButtonHash.setDisable(true);
                    processMenuForHashButtonHashActivate.setDisable(true);
                    hashMessageForHash.setEditable(false);
                    copyHashFileButtonForHash.setVisible(true);
                }
            }
            else {
                processMenuForHashButtonFileHashEnter.setDisable(false);
                processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                processMenuForHashButtonHash.setDisable(false);
                processMenuForHashButtonHashActivate.setDisable(true);
                processMenuForHashButtonFileHash.setDisable(false);
                processMenuForHashButtonFileHashActivate.setDisable(true);
                hashMessageForHash.setEditable(true);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForHashButtonFileHashActivate.setOnAction(e -> {
            processMenuForHash.getChildren().removeAll(firstGridHash);
            processMenuForHashButtonFileHashEnter.setDisable(false);
            processMenuForHashButtonFileHashEnterActivate.setDisable(true);
            processMenuForHashButtonHash.setDisable(false);
            processMenuForHashButtonHashActivate.setDisable(true);
            processMenuForHashButtonFileHash.setDisable(false);
            processMenuForHashButtonFileHashActivate.setDisable(true);
            hashMessageForHash.setEditable(true);
        });

        processMenuForHashButtonFileMatchEnter.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Dosya Seç");
            selectedFile = fileChooser.showOpenDialog(stage);
            wrotedMessageMatching = matchMessageForHash.getText();
            if (selectedFile != null) {
                processMenuForHashButtonFileMatchEnter.setDisable(true);
                processMenuForHashButtonFileMatchEnterActivate.setDisable(false);
                processMenuForHashButtonMatch.setDisable(true);
                processMenuForHashButtonMatchActivate.setDisable(true);
                processMenuForHashButtonFileMatch.setDisable(false);
                processMenuForHashButtonFileMatchActivate.setDisable(true);
                matchMessageForHash.setEditable(false);
                matchMessageForHash.clear();
                selectedFileName = selectedFile.getName();
                matchMessageForHash.appendText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                //alertEntering.setHeaderText("Giriş Başarılı");
                //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
                //alertEntering.showAndWait();
            }
            else {
                processMenuForHashButtonFileMatchEnter.setDisable(false);
                processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                processMenuForHashButtonMatch.setDisable(false);
                processMenuForHashButtonMatchActivate.setDisable(true);
                processMenuForHashButtonFileMatch.setDisable(false);
                processMenuForHashButtonFileMatchActivate.setDisable(true);
                matchMessageForHash.setEditable(true);
                matchMessageForHash.clear();
                matchMessageForHash.appendText(wrotedMessageMatching);
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
            }
        });

        processMenuForHashButtonFileMatchEnterActivate.setOnAction(e -> {
            processMenuForHashButtonFileMatchEnter.setDisable(false);
            processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
            processMenuForHashButtonMatch.setDisable(false);
            processMenuForHashButtonMatchActivate.setDisable(true);
            processMenuForHashButtonFileMatch.setDisable(false);
            processMenuForHashButtonFileMatchActivate.setDisable(true);
            matchMessageForHash.setEditable(true);
            matchMessageForHash.clear();
            matchMessageForHash.appendText(wrotedMessageMatching);
        });

        processMenuForHashButtonMatch.setOnAction(e -> {
            String userInputMatch = matchMessageForHash.getText();
            String userInputHash = hashForHash.getText();
            try {
                matchContent = Algoritmalar.startMessage(algoritma, "Doğrula", "Doğrula", userInputMatch, "Doğrula", userInputHash);
            } catch (Exception error) {
                showErrorMessage("Girilen Hash Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (matchContent.equals("Giriş Yapılmadı.")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şüphelendiğiniz Metni ve Hashi Girin");
                alertEntering.showAndWait();
                processMenuForHashButtonFileMatchEnter.setDisable(false);
                processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                processMenuForHashButtonMatch.setDisable(false);
                processMenuForHashButtonMatchActivate.setDisable(true);
                processMenuForHashButtonFileMatch.setDisable(false);
                processMenuForHashButtonFileMatchActivate.setDisable(true);
                matchMessageForHash.setEditable(true);
                hashForHash.setEditable(true);
            }

            else {
                if (matchContent.equals("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)")) {
                    Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                    alertEntering.setHeaderText("Dikkat");
                    alertEntering.setContentText("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                    alertEntering.showAndWait();
                    processMenuForHashButtonFileMatchEnter.setDisable(true);
                    processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                    processMenuForHashButtonMatch.setDisable(true);
                    processMenuForHashButtonMatchActivate.setDisable(false);
                    processMenuForHashButtonFileMatch.setDisable(true);
                    processMenuForHashButtonFileMatchActivate.setDisable(true);
                    matchMessageForHash.setEditable(false);
                    hashForHash.setEditable(false);
                }
                if (matchContent.equals("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)")) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Sorun Yok");
                    alertEntering.setContentText("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                    alertEntering.showAndWait();
                    processMenuForHashButtonFileMatchEnter.setDisable(true);
                    processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                    processMenuForHashButtonMatch.setDisable(true);
                    processMenuForHashButtonMatchActivate.setDisable(false);
                    processMenuForHashButtonFileMatch.setDisable(true);
                    processMenuForHashButtonFileMatchActivate.setDisable(true);
                    matchMessageForHash.setEditable(false);
                    hashForHash.setEditable(false);
                }
            }
        });

        processMenuForHashButtonMatchActivate.setOnAction(e -> {
            processMenuForHashButtonFileMatchEnter.setDisable(false);
            processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
            processMenuForHashButtonMatch.setDisable(false);
            processMenuForHashButtonMatchActivate.setDisable(true);
            processMenuForHashButtonFileMatch.setDisable(false);
            processMenuForHashButtonFileMatchActivate.setDisable(true);
            matchMessageForHash.setEditable(true);
            hashForHash.setEditable(true);
        });

        processMenuForHashButtonFileMatch.setOnAction(e -> {
            if (selectedFile != null) {
                byte[] fileBytes;
                try {
                    fileBytes = Files.readAllBytes(selectedFile.toPath());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                String[] fileFormat = selectedFileName.split("\\.");
                byte[] fileFormatBytes;
                try {
                    fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
                } catch (UnsupportedEncodingException ee) {
                    throw new RuntimeException(ee);
                }

                byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
                byte[] fileBytesFinal = new byte[fileBytes.length+9+fileFormatBytes.length];
                System.arraycopy(fileBytes, 0, fileBytesFinal, 0, fileBytes.length);
                System.arraycopy(numbers, 0, fileBytesFinal, fileBytes.length, 9);
                System.arraycopy(fileFormatBytes, 0, fileBytesFinal, fileBytes.length+9, fileFormatBytes.length);

                String userInputHash = hashForHash.getText();

                try {
                    matchContentBytes = Algoritmalar.startFile(algoritma, null, "Doğrula", fileBytesFinal, null, userInputHash);
                } catch (Exception error) {
                    showErrorMessage("Girilen Hash Hatalıdır.");
                    throw new RuntimeException(error);
                }

                if (matchContentBytes == null) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Giriş Yapılmadı");
                    alertEntering.setContentText("Lütfen Şüphelendiğiniz Metni ve Hashi Girin");
                    alertEntering.showAndWait();
                    processMenuForHashButtonFileMatchEnter.setDisable(false);
                    processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                    processMenuForHashButtonMatch.setDisable(true);
                    processMenuForHashButtonMatchActivate.setDisable(true);
                    processMenuForHashButtonFileMatch.setDisable(false);
                    processMenuForHashButtonFileMatchActivate.setDisable(true);
                    hashMessageForHash.setEditable(true);
                    hashForHash.setEditable(true);
                } else {
                    if (bytesToHex(matchContentBytes).equals("3131")) {
                        Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                        alertEntering.setHeaderText("Dikkat");
                        alertEntering.setContentText("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                        alertEntering.showAndWait();
                        processMenuForHashButtonFileMatchEnter.setDisable(true);
                        processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                        processMenuForHashButtonMatch.setDisable(true);
                        processMenuForHashButtonMatchActivate.setDisable(true);
                        processMenuForHashButtonFileMatch.setDisable(true);
                        processMenuForHashButtonFileMatchActivate.setDisable(false);
                        matchMessageForHash.setEditable(false);
                        hashForHash.setEditable(false);
                    }
                    if (bytesToHex(matchContentBytes).equals("31")) {
                        Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                        alertEntering.setHeaderText("Sorun Yok");
                        alertEntering.setContentText("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                        alertEntering.showAndWait();
                        processMenuForHashButtonFileMatchEnter.setDisable(true);
                        processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                        processMenuForHashButtonMatch.setDisable(true);
                        processMenuForHashButtonMatchActivate.setDisable(true);
                        processMenuForHashButtonFileMatch.setDisable(true);
                        processMenuForHashButtonFileMatchActivate.setDisable(false);
                        matchMessageForHash.setEditable(false);
                        hashForHash.setEditable(false);
                    }
                }
            }
        });

        processMenuForHashButtonFileMatchActivate.setOnAction(e -> {
            processMenuForHash.getChildren().removeAll(secondGridHash);
            processMenuForHashButtonFileMatchEnter.setDisable(false);
            processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
            processMenuForHashButtonMatch.setDisable(false);
            processMenuForHashButtonMatchActivate.setDisable(true);
            processMenuForHashButtonFileMatch.setDisable(false);
            processMenuForHashButtonFileMatchActivate.setDisable(true);
            matchMessageForHash.setEditable(true);
            hashForHash.setEditable(true);
        });

        copyHashButtonForHash.setOnAction(e -> {
            String[] hash = hashInfo.getText().split("! ");
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(hash[1]);
            clipboard.setContent(content);

            Alert hashCopy = new Alert(Alert.AlertType.INFORMATION);
            hashCopy.setHeaderText("Hash Kopyalandı");
            hashCopy.showAndWait();
        });

        copyHashFileButtonForHash.setOnAction(e -> {
            String[] fileFormat = selectedFileName.split("\\.");
            byte[] fileFormatBytes;
            try {
                fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
            } catch (UnsupportedEncodingException ee) {
                throw new RuntimeException(ee);
            }

            String keyInfoHex = bytesToHex(hashContentBytes);
            String fileFormatHex = bytesToHex(fileFormatBytes);
            String finalKeyHex = keyInfoHex + ":" + fileFormatHex;

            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(finalKeyHex);
            clipboard.setContent(content);

            Alert keyCopy = new Alert(Alert.AlertType.INFORMATION);
            keyCopy.setHeaderText("Hash Kopyalandı");
            keyCopy.showAndWait();
        });
    }










    private void clearSelections(ToggleGroup... groups){
        for (ToggleGroup group : groups){
            if (group.getSelectedToggle() != null){
                group.getSelectedToggle().setSelected(false);
            }
        }
    }


    private void updateConfirmButtonState(RadioButton selectedMetod, int controlNumber){
        if (controlNumber == 1){
            confirmButton.setDisable(false);
            selectedMetodLast = selectedMetod;
        } else{
            confirmButton.setDisable(true);
        }
    }


    public String getSelectedAlgorithm(){
        if (selectedMetodLast == desOption) return "Simetrik Şifreleme: DES Algoritması";
        if (selectedMetodLast == threeDesOption) return "Simetrik Şifreleme: 3DES Algoritması";
        if (selectedMetodLast == aesOption) return "Simetrik Şifreleme: AES Algoritması";

        if (selectedMetodLast == rsaOptionEncrypt) return "Asimetrik Şifreleme: RSA Algoritması";
        if (selectedMetodLast == eciesOption) return "Asimetrik Şifreleme: ECIES Algoritması";

        if (selectedMetodLast == rsaOptionSign) return "İmzalama: RSA Algoritması";
        if (selectedMetodLast == ecdsaOption) return "İmzalama: ECDSA Algoritması";
        if (selectedMetodLast == dsaOption) return "İmzalama: DSA Algoritması";

        if (selectedMetodLast == md5Option) return "Hash: MD5 Algoritması";
        if (selectedMetodLast == sha1Option) return "Hash: SHA-1 Algoritması";
        if (selectedMetodLast == sha256Option) return "Hash: SHA-256 Algoritması";
        if (selectedMetodLast == sha3Option) return "Hash: SHA-3 Algoritması";
        if (selectedMetodLast == sha512Option) return "Hash: SHA-512 Algoritması";
        if (selectedMetodLast == blake2Option) return "Hash: BLAKE2 Algoritması";
        if (selectedMetodLast == argon2Option) return "Hash: Argon2 Algoritması";

        if (selectedMetodLast == smartCardOption) return "Akıllı Kart";

        return null;
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
