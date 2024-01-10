package company;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class AsymmetricEncryptionUtil {

    public static String encryptWithPublicKey(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(secretKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static SecretKey decryptWithPrivateKey(String encryptedSecretKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedSecretKey));
        return new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, "AES");
    }
}
