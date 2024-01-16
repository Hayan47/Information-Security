package company.Utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;
public class SymmetricEncryptionUtil {
    private static final String salt = "hfdom" ;

    public static SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // or 256 for stronger encryption
        return keyGenerator.generateKey();
    }


    public static SecretKey deriveKeyFromUsername(String username) throws Exception {
        KeySpec spec = new PBEKeySpec(username.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        return  secretKey;
    }

    public static String encrypt(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }
}
