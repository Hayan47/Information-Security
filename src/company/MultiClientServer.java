package company;
import company.DatabaseConncetion.*;
import company.Utils.*;
import org.json.JSONObject;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;;


public class MultiClientServer {
    private static final int PORT = 11111;
    private static final ExecutorService pool = Executors.newFixedThreadPool(10); // Thread pool for handling multiple clients
    private static PrivateKey serverPrivateKey;
    private static PublicKey serverPublicKey;
    private static PublicKey clientPublicKey;


    public static void main(String[] args) throws Exception {
        initializeServerKeys();
        startServer();
    }

    private static void initializeServerKeys() throws Exception {
        // Initialize server keys
        KeyPairGeneratorUtil keyPairUtil = new KeyPairGeneratorUtil();
        serverPublicKey = keyPairUtil.getPublicKey();
        serverPrivateKey = keyPairUtil.getPrivateKey();
    }

    private static void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("The server is running...");
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

            clientPublicKey = exchangeKeysWithClient(objectIn, objectOut);
            SecretKey sessionKey = decryptSessionKey(objectIn, objectOut);

            ClientHandler clientHandler = new ClientHandler(clientSocket, sessionKey, objectIn, objectOut);
            pool.execute(clientHandler);
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error handling client connection: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey exchangeKeysWithClient(ObjectInputStream objectIn, ObjectOutputStream objectOut) throws IOException, ClassNotFoundException {
        PublicKey clientPublicKey = (PublicKey) objectIn.readObject();
        objectOut.writeObject(serverPublicKey);
        return clientPublicKey;
    }

    private static SecretKey decryptSessionKey(ObjectInputStream objectIn, ObjectOutputStream objectOut) throws Exception {
        String encryptedSessionKey = (String) objectIn.readObject();
        SecretKey sessionKey = AsymmetricEncryptionUtil.decryptWithPrivateKey(encryptedSessionKey, serverPrivateKey);
        JSONObject confirmation = new JSONObject();
        confirmation.put("status", "success");
        confirmation.put("message", "Session key received and accepted");
        objectOut.writeObject(confirmation.toString());
        objectOut.flush();

        return sessionKey;
    }

    static class ClientHandler implements Runnable {
        private Socket socket;
        private SecretKey sessionKey;
        private String name;
        private String password;
        private String role;
        private ObjectInputStream objectIn;
        private ObjectOutputStream objectOut;

        public ClientHandler(Socket socket, SecretKey sessionKey, ObjectInputStream objectIn, ObjectOutputStream objectOut) {
            this.socket = socket;
            this.sessionKey = sessionKey;
            this.objectIn = objectIn;
            this.objectOut = objectOut;
        }

        @Override
        public void run() {
            try {
                processClientRequests();
            } catch (Exception e) {
                System.err.println("ClientHandler exception: " + e.getMessage());
                e.printStackTrace();
            } finally {
//                closeResources();
            }
        }

        private void processClientRequests() throws Exception {
            while(true){
                try{
                    String request = (String) objectIn.readObject();
                    JSONObject requestJson = new JSONObject(request);
                    String action = requestJson.getString("action");

                    switch (action) {
                        case "login":
                            processLogin(requestJson);
                            break;
                        case "add":
                            processAddNumber(requestJson);
                            break;
                        case "sendMessage":
                            processSendMessage(requestJson);
                            break;
                        case "addMarks":
                            processAddMarks(requestJson);
                            break;
                        case "showMarks":
                            processShowMarks(requestJson);
                            break;
                        default:
                            System.err.println("Unknown action: " + action);
                    }
                }catch (Exception e){
                    System.out.println(e.getMessage());
                    break;
                }
            }
        }

        private void processLogin(JSONObject requestJson) throws IOException {
            name = requestJson.getString("name");
            password = requestJson.getString("password");
            role = requestJson.getString("role");
            Login login = new Login(name, password, role);
            boolean loginResult = login.login();
            JSONObject loginResponse = new JSONObject();
            loginResponse.put("status", loginResult);
            objectOut.writeObject(loginResponse.toString());
            objectOut.flush();
        }

        private void processAddNumber(JSONObject requestJson) throws Exception {
            String encryptedNumber = requestJson.getString("number");
            System.out.println("Encrypted Number: " + encryptedNumber);
            SecretKey secretKey = SymmetricEncryptionUtil.deriveKeyFromUsername(name);
            String decryptedNumber = SymmetricEncryptionUtil.decrypt(encryptedNumber, secretKey);
            System.out.println("Decrypted Number: " + decryptedNumber);
            AddNumber add = new AddNumber();
            boolean addResult = add.addNumber(name, Integer.parseInt(decryptedNumber));
            JSONObject addNumberResponse = new JSONObject();
            addNumberResponse.put("status", addResult);
            objectOut.writeObject(addNumberResponse.toString());
            objectOut.flush();
        }

        private void processSendMessage(JSONObject requestJson) throws Exception {
            String encryptedMessage = requestJson.getString("message");
            System.out.println("Encrypted Message: " + encryptedMessage);
            String message = SymmetricEncryptionUtil.decrypt(encryptedMessage, sessionKey);
            System.out.println("Decrypted Message: " + message);
            AddMessage add = new AddMessage();
            boolean addResult = add.addMessage(name, message);
            String encryptedResponse = SymmetricEncryptionUtil.encrypt(String.valueOf(addResult), sessionKey);
            objectOut.writeUTF(encryptedResponse);
            objectOut.flush();
        }

        private void closeResources() {
            try {
                if (objectOut != null) {
                    objectOut.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing ObjectOutputStream: " + e.getMessage());
            }

            try {
                if (objectIn != null) {
                    objectIn.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing ObjectInputStream: " + e.getMessage());
            }

            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing Socket: " + e.getMessage());
            }

        }

        private void processAddMarks(JSONObject requestJson) throws IOException {
            String studentName = requestJson.getString("student_name");
            String marks = requestJson.getString("marks");
            String signature = objectIn.readUTF();
            boolean verified = DigitalSignatureUtil.verifySignature(requestJson.toString(), signature, clientPublicKey);
            if (verified){
                AddMarks add = new AddMarks();
                String addResult = add.addMarks(studentName, marks);
                objectOut.writeObject(addResult);
            }
        }

        private void processShowMarks(JSONObject requestJson) throws Exception {
            String studentName = requestJson.getString("student_name");
            byte[] receivedCertificateBytes = (byte[]) objectIn.readObject();
            // Convert the byte array back to an X509Certificate
            X509Certificate receivedCertificate = CertificateUtil.convertBytesToX509Certificate(receivedCertificateBytes);
            // Verify the received certificate
            PublicKey caPublicKey = getCaPublicKey();
            boolean verified = CertificateUtil.verifyCertificate(receivedCertificate, caPublicKey);
            if(verified){
                GetMarks getMarks = new GetMarks();
                String marks = getMarks.getMarks(studentName);
                objectOut.writeUTF(marks);
                objectOut.flush();
            }else{
                objectOut.writeUTF("NOT VERIFIED");
                objectOut.flush();
            }
        }

        private PublicKey getCaPublicKey() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            char[] password = "Hayan".toCharArray();
            try (FileInputStream fis = new FileInputStream("CAkeystore.jks")) {
                keyStore.load(fis, password);
            }
            // Retrieve the CA's public key from the keystore
            String alias = "alias"; // Use the alias you used when storing the key pair in the keystore
            Certificate certificate = keyStore.getCertificate(alias);
            PublicKey caPublicKey = certificate.getPublicKey();
            // For example, you can print the encoded form of the public key
            System.out.println("CA's Public Key: " + java.util.Base64.getEncoder().encodeToString(caPublicKey.getEncoded()));
            return caPublicKey;
        }
    }
}

