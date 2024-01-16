package company.Utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class CertificateUtil {
    public static PKCS10CertificationRequest generateCSR(PublicKey publicKey, PrivateKey privateKey, String subjectDN) throws Exception {
        // Create a subject for the CSR. Modify with appropriate details.
        X500Name subject = new X500Name(subjectDN);
        // Create the SubjectPublicKeyInfo for the public key
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        // Create a builder for the CSR
        PKCS10CertificationRequestBuilder p10Builder = new PKCS10CertificationRequestBuilder(subject, subjectPublicKeyInfo);
        // Specify the signature algorithm
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        // Sign the CSR using the private key
        ContentSigner signer = csBuilder.build(privateKey);
        return p10Builder.build(signer);
    }
    public static X509Certificate convertBytesToX509Certificate(byte[] certificateBytes)
            throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certificateBytes);
        return (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);
    }

    public static X509Certificate signCertificate(PKCS10CertificationRequest csr, PrivateKey caPrivateKey) {
        try{
            //issuer name
            X500Name issuerName = new X500Name("CN=Damascus University, O=Damascus University, L=Damascus, ST=Syria, C=Syria");
            // Extract public key from CSR
            PublicKey userPublicKey = extractPublicKeyFromCSR(csr);
            // Certificate validity
            Date startDate = new Date();
            Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); // 1 year validity
            // Serial Number
            BigInteger serialNumber = new BigInteger(64, new SecureRandom());
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuerName,
                    serialNumber,
                    startDate,
                    endDate,
                    csr.getSubject(),
                    userPublicKey
            );
            // Basic Constraints - false for end entities (not a CA)
            BasicConstraints basicConstraints = new BasicConstraints(false);
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints.toASN1Primitive());
            // Other extensions (if needed)
            // certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
            return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        }catch (Exception e){
            System.out.println(e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static PublicKey extractPublicKeyFromCSR(PKCS10CertificationRequest csr) {
        try {
            SubjectPublicKeyInfo publicKeyInfo = csr.getSubjectPublicKeyInfo();
            return KeyFactory.getInstance(publicKeyInfo.getAlgorithm().getAlgorithm().getId())
                    .generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verifyCertificate(X509Certificate certificate, PublicKey caPublicKey) {
        try {
            // Check if the certificate is currently valid
            certificate.checkValidity();
            // Verify the certificate's signature using its public key
            certificate.verify(caPublicKey);
            // If the certificate passes these checks, consider it valid
            return true;
        } catch (Exception e) {
            // Handle other unexpected exceptions
            e.printStackTrace();
            return false;
        }
    }

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        X500Name issuerName = new X500Name("CN=Damascus University, O=Damascus University, L=Damascus, ST=Syria, C=Syria");
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); // 1 year validity
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                issuerName,
                keyPair.getPublic()
        );
        // Basic Constraints - false for end entities (not a CA)
        BasicConstraints basicConstraints = new BasicConstraints(false);
        certificateBuilder.addExtension(Extension.basicConstraints, true, basicConstraints.toASN1Primitive());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
    }

}
