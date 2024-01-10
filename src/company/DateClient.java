package company;
import org.json.JSONObject;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;



public class DateClient {
    private static final String SERVER_ADDRESS = "127.0.0.1";
    private static final int SERVER_PORT = 11111;
    private Socket socket;
    private ObjectOutputStream objectOut;
    private ObjectInputStream objectIn;
    private Scanner scanner;
    private boolean isLogged;
    private PublicKey clientPublicKey;
    private PrivateKey clientPrivateKey;
    private SecretKey sessionKey;
    String name = "";
    String password = "";
    String role = "";

    public static void main(String[] args) throws Exception {
        DateClient client = new DateClient();
        client.runClient();
    }
    private void runClient() {
        try {
            setupConnection();
            performLogin();
            if (isLogged) {
                showMenu();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            closeResources();
        }
    }
    private void setupConnection() throws Exception {
        // Establish a connection with the server
        socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        objectOut = new ObjectOutputStream(socket.getOutputStream());
        objectOut.flush();
        objectIn = new ObjectInputStream(socket.getInputStream());
        scanner = new Scanner(System.in);
        // Key exchange and session key setup
        KeyPairGeneratorUtil keyPairUtil = new KeyPairGeneratorUtil();
        clientPublicKey = keyPairUtil.getPublicKey();
        System.out.println("Client Public Key: " + clientPublicKey);
        clientPrivateKey = keyPairUtil.getPrivateKey();
        // Send client's public key to server
        objectOut.writeObject(clientPublicKey);
        // Receive server's public key
        PublicKey serverPublicKey = (PublicKey) objectIn.readObject();
        System.out.println("Server Public Key: " + serverPublicKey);
        // Generate and encrypt session key
        sessionKey = SymmetricEncryptionUtil.generateSymmetricKey();
        System.out.println("Session Key: " + sessionKey);
        String encryptedSessionKey = AsymmetricEncryptionUtil.encryptWithPublicKey(sessionKey, serverPublicKey);
        System.out.println("Encrypted Session Key: " + encryptedSessionKey);
        // Send encrypted session key to server
        objectOut.writeObject(encryptedSessionKey);
        // Receive response from server
        String res = (String) objectIn.readObject();
        JSONObject resJson = new JSONObject(res);
        System.out.println("status : " + resJson.getString("status") + "\nmessage : " + resJson.getString("message"));

    }
    private void performLogin() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        System.out.print("Enter your name: ");
        name = scanner.next();
        System.out.print("Enter your password: ");
        password = scanner.next();
        String hashedPassword = Hash.hashPassword(password);
        System.out.print("Enter your role(s for student, d for doctor): ");
        role = scanner.next();

        JSONObject login = new JSONObject();
        login.put("action", "login");
        login.put("name", name);
        login.put("password", hashedPassword);
        login.put("role", role);
        objectOut.writeObject(login.toString());

        String loginResponse =(String) objectIn.readObject();
        JSONObject loginResponseJson = new JSONObject(loginResponse);
        isLogged = loginResponseJson.getBoolean("status");
        if (isLogged) System.out.println("login successful");
        if (!isLogged) {
            System.out.println("Invalid name or password");
        }
    }
    private void showMenu() throws IOException {
        while (true) {
            System.out.println("1 - Add Number");
            System.out.println("2 - Send Message");
            System.out.println("3 - End Program");
            if (role.equals("d")){
                System.out.println("4 - Add Marks");
            }
            int choice = scanner.nextInt();

            switch (choice) {
                case 1:
                    addNumber();
                    break;
                case 2:
                    sendMessage();
                    break;
                case 3:
                    closeResources();
                    return;
                case 4:
                    addMarks();
                    break;
                default:
                    System.out.println("Invalid option.");
            }
        }
    }
    private void addNumber() {
        System.out.println("Enter the number:");
        int number = scanner.nextInt();

        try {
            // Encrypt the number here
            SecretKey secretKey = SymmetricEncryptionUtil.deriveKeyFromUsername(name);
            String encryptedNumber = SymmetricEncryptionUtil.encrypt(String.valueOf(number), secretKey);
            System.out.println("Encrypted Number: " + encryptedNumber);
            // Send the command and encrypted number to the server
            JSONObject addNumber = new JSONObject();
            addNumber.put("action", "add");
            addNumber.put("number", encryptedNumber);
            objectOut.writeObject(addNumber.toString());
            objectOut.flush();

            String addNumberResponse = (String) objectIn.readObject();
            JSONObject addNumberResponseJson = new JSONObject(addNumberResponse);
            Boolean result = addNumberResponseJson.getBoolean("status");
            if (result) {
                System.out.println("Number Added Successfully");
            } else {
                System.out.println("Failed to add number");
            }
        } catch (Exception e) {
            System.out.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    private void sendMessage() {
        System.out.println("Enter your message:");
        scanner.nextLine();  // Consume the leftover newline
        String userMessage = scanner.nextLine();

        try {
            // Encrypt the message
            String encryptedMessage = SymmetricEncryptionUtil.encrypt(userMessage, sessionKey);
            System.out.println("Encrypted Number: " + encryptedMessage);
            // Send the command and encrypted message to the server
            JSONObject addMessage = new JSONObject();
            addMessage.put("action", "sendMessage");
            addMessage.put("message", encryptedMessage);
            objectOut.writeObject(addMessage.toString());
            objectOut.flush();
            // Receive and decrypt the response from the server
            String encryptedResponse = objectIn.readUTF();
            String decryptedResponse = SymmetricEncryptionUtil.decrypt(encryptedResponse, sessionKey);
            System.out.println("Server response: " + decryptedResponse);
        } catch (Exception e) {
            System.out.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void closeResources() {
        try {
            if (objectOut != null) {
                objectOut.close();
            }
        } catch (IOException e) {
            System.out.println("Error closing output stream: " + e.getMessage());
        }

        try {
            if (objectIn != null) {
                objectIn.close();
            }
        } catch (IOException e) {
            System.out.println("Error closing input stream: " + e.getMessage());
        }

        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            System.out.println("Error closing socket: " + e.getMessage());
        }

        if (scanner != null) {
            scanner.close();
        }
    }

    private void addMarks() {
        System.out.println("Enter Student name: ");
        scanner.nextLine();
        String studentName = scanner.nextLine();
        System.out.println("Enter Marks List: ");
        String marks = scanner.nextLine();

        try{
            JSONObject addMarks = new JSONObject();
            addMarks.put("action", "addMarks");
            addMarks.put("student_name", studentName);
            addMarks.put("marks", marks);

            // Generate digital signature
            String signature = DigitalSignature.generateSignature(addMarks.toString(), clientPrivateKey);
            objectOut.writeObject(addMarks.toString());
            objectOut.writeUTF(signature);
            objectOut.flush();

            //response
            String addMarksResponse = (String) objectIn.readObject();
            JSONObject addMarksResponseJson = new JSONObject(addMarksResponse);
            int id = addMarksResponseJson.getInt("id");
            String created_at = addMarksResponseJson.getString("createdAt");
            System.out.println("id: " + id);
            System.out.println("created at: " + created_at);


        } catch (Exception e){
            System.out.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }

    }


}

