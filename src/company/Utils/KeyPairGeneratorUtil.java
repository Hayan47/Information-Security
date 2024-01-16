package company.Utils;

import java.security.*;
import java.security.cert.Certificate;

public class KeyPairGeneratorUtil{
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair keyPair;

    public KeyPairGeneratorUtil() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public static KeyPair getKeyPairFromKeyStore(KeyStore keyStore, String alias, char[] password) throws Exception {
        // Retrieve the private key and public key from the keystore using the alias
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        Certificate cert = keyStore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }
}
