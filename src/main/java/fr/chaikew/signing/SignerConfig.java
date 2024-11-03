package fr.chaikew.signing;


import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

public class SignerConfig {
    static {
        // use SpongyCastle as security provider
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
        //Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public static final SignerConfig DEFAULT_CONFIG = new SignerConfig(
            "000000".toCharArray(),
            "key0",
            "000000".toCharArray(),
            "keystore.bks"
    );

    public final char[] keystorePassword;
    public final String keystoreEntryName;
    public final char[] keystoreEntryPassword;
    public final String keystorePath;

    public SignerConfig(char[] keystorePassword, String keystoreEntryName, char[] keystoreEntryPassword, String keystorePath) {
        this.keystorePassword = keystorePassword;
        this.keystoreEntryName = keystoreEntryName;
        this.keystoreEntryPassword = keystoreEntryPassword;
        this.keystorePath = keystorePath;
    }

    public SignerConfig withPath(String newPath) {
        return new SignerConfig(keystorePassword, keystoreEntryName, keystoreEntryPassword, newPath);
    }

    public SignedJar createSignedJar(OutputStream pZApk) throws SecurityException, IOException {
        if (!new File(this.keystorePath).exists()) {
            createKeystore();
        }

        try (
                InputStream keyStoreInputStream = Files.newInputStream(new File(this.keystorePath).toPath())
        ) {
            KeyStore keyStore = KeyStore.getInstance("BKS");
            keyStore.load(keyStoreInputStream, this.keystorePassword);

            KeyStore.PrivateKeyEntry keyStoreEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                    this.keystoreEntryName, new KeyStore.PasswordProtection(this.keystoreEntryPassword)
            );

            return new SignedJar(
                    pZApk,
                    Arrays.asList((X509Certificate[]) keyStoreEntry.getCertificateChain()),
                    (X509Certificate) keyStoreEntry.getCertificate(),
                    keyStoreEntry.getPrivateKey()
            );
        } catch (UnrecoverableEntryException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new SecurityException(e);
        }
    }

    private void createKeystore() throws SecurityException, IOException {
        try {
            // Add Bouncy Castle as a security provider
            Security.addProvider(new BouncyCastleProvider());

            // Generate a key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Create a self-signed certificate
            X500Name issuer = new X500Name("CN=SelfCert");
            X500Name subject = new X500Name("CN=SelfCert");
            Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24);
            Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365);
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    new BigInteger(256, new SecureRandom()),
                    notBefore,
                    notAfter,
                    subject,
                    keyPair.getPublic());

            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));


            // Use BKS keystore type
            java.security.KeyStore keystore = java.security.KeyStore.getInstance("BKS");
            keystore.load(null, this.keystorePassword);
            keystore.setKeyEntry(this.keystoreEntryName, keyPair.getPrivate(), this.keystoreEntryPassword, new java.security.cert.Certificate[]{certificate});

            // Save the keystore to a file
            try (FileOutputStream fos = new FileOutputStream(this.keystorePath)) {
                keystore.store(fos, this.keystorePassword);
            }
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | OperatorCreationException e) {
            throw new SecurityException(e);
        }
    }
}