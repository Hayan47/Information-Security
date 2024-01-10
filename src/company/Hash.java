package company;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
public class Hash {
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = md.digest(password.getBytes());

        StringBuilder hexString = new StringBuilder();
        for (byte hashedByte : hashedBytes) {
            String hex = Integer.toHexString(0xff & hashedByte);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }
}
