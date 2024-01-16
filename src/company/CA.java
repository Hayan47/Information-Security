package company;

import company.Utils.CertificateUtil;
import company.Utils.KeyPairGeneratorUtil;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;

import static company.Utils.CertificateUtil.generateSelfSignedCertificate;

public class CA {
    private static PublicKey caPublicKey;
    private static PrivateKey caPrivateKey;
    private static X509Certificate caCertificate;

    public static void main(String[] args) throws Exception {
        initializeCAKeys();
        startServer();
    }
    private static void initializeCAKeys() throws Exception {
        // Check if the keystore file exists
        File keystoreFile = new File("CAKeystore.jks");
        if (keystoreFile.exists()) {
            // If the keystore file exists, load keys from it
            KeyStore keyStore = KeyStore.getInstance("JKS");
            char[] password = "Hayan".toCharArray();
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, password);
            }
            // Retrieve the private key and public key from the keystore
            KeyPair keyPair = KeyPairGeneratorUtil.getKeyPairFromKeyStore(keyStore, "alias", password);
            caPrivateKey = keyPair.getPrivate();
            caPublicKey = keyPair.getPublic();
        } else {
            // Initialize server keys
            KeyPairGeneratorUtil keyPairUtil = new KeyPairGeneratorUtil();
            caPublicKey = keyPairUtil.getPublicKey();
            caPrivateKey = keyPairUtil.getPrivateKey();
            // Create a KeyStore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            char[] password = "Hayan".toCharArray();
            keyStore.load(null, password);
            X509Certificate selfSignedCertificate = generateSelfSignedCertificate(keyPairUtil.getKeyPair());
            // Store private key and public key in the keystore
            keyStore.setKeyEntry("alias", caPrivateKey, password, new java.security.cert.Certificate[]{selfSignedCertificate});
            // Save the keystore to a file
            keyStore.store(new java.io.FileOutputStream("CAKeystore.jks"), password);
        }

    }

    private static void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(22222)) {
            System.out.println("The CA is running...");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                handleClientConnection(clientSocket);
            }
        } catch (IOException e) {
            System.err.println("Server exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    private static void handleClientConnection(Socket clientSocket) {
        try {
            ObjectOutputStream objectOut = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream objectIn = new ObjectInputStream(clientSocket.getInputStream());
            byte[] receivedCsrBytes = (byte[]) objectIn.readObject();
            // Convert the received byte array back to a PKCS10CertificationRequest object
            PKCS10CertificationRequest receivedCsr = new PKCS10CertificationRequest(receivedCsrBytes);
            // Process the received CSR as needed
            System.out.println("Received CSR: " + receivedCsr);
            System.out.println(receivedCsr.getSubjectPublicKeyInfo());
            // send a math equation
            String mathEquation = generateMathEquation();
            System.out.println(mathEquation);
            objectOut.writeUTF(mathEquation);
            objectOut.flush();
            //receive the solution
            int clientSolution = Integer.parseInt(objectIn.readUTF());
            System.out.println(clientSolution);

            if (validateSolution(mathEquation, clientSolution)) {
                // Authentication successful
                System.out.println("Success");
                objectOut.writeUTF("Authentication successful");
                objectOut.flush();
                // sign the certificate
                X509Certificate signedCertificate = CertificateUtil.signCertificate(receivedCsr, caPrivateKey);
                System.out.println(signedCertificate);
                //send it to user
                byte[] certificateBytes = signedCertificate.getEncoded();
                objectOut.writeObject(certificateBytes);
                objectOut.flush();
            } else {
                // Authentication failed
                System.out.println("Failed");
                objectOut.writeUTF("Authentication failed");
                objectOut.flush();
            }
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error handling client connection: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean validateSolution(String equation, int clientSolution) {
        int correctSolution = solveMathEquation(equation);
        return clientSolution == correctSolution;
    }

    private static int solveMathEquation(String equation) {
        String[] parts = equation.split(" ");
        int operand1 = Integer.parseInt(parts[0]);
        int operand2 = Integer.parseInt(parts[2]);
        char operator = parts[1].charAt(0);

        switch (operator) {
            case '+':
                return operand1 + operand2;
            case '-':
                return operand1 - operand2;
            case '*':
                return operand1 * operand2;
            default:
                throw new IllegalArgumentException("Invalid operator: " + operator);
        }
    }
    private static String generateMathEquation() {
        SecureRandom random = new SecureRandom();

        int operand1 = random.nextInt(10) + 1;  // Random number between 1 and 10
        int operand2 = random.nextInt(10) + 1;  // Random number between 1 and 10

        char operator = generateRandomOperator();

        return String.format("%d %s %d", operand1, operator, operand2);
    }

    private static char generateRandomOperator() {
        char[] operators = {'+', '-', '*'};
        SecureRandom random = new SecureRandom();
        return operators[random.nextInt(operators.length)];
    }

}

