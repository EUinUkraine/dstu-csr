package org.alan;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;

import static org.apache.commons.io.FileUtils.*;
import static org.apache.commons.io.FileUtils.writeByteArrayToFile;
import static sun.java2d.cmm.ColorTransform.Out;

public class Main {
     public static void main(String[] args) throws OperatorCreationException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
         Security.addProvider(new BouncyCastleProvider());

         ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
         KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
         g.initialize(ecSpec, new SecureRandom());
         KeyPair pair = g.generateKeyPair();

         JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_128_CBC);
         encryptorBuilder.setRandom(new SecureRandom());
         encryptorBuilder.setPasssword("123456".toCharArray());
         OutputEncryptor encryptor = encryptorBuilder.build();

         JcaPKCS8Generator pkcs8 = new JcaPKCS8Generator(pair.getPrivate(), encryptor );
         JcaPEMWriter privateKeyWriter = new JcaPEMWriter(new FileWriter("private.pem"));
         PemObject pemkey = pkcs8.generate();
         privateKeyWriter.writeObject(pemkey);
         privateKeyWriter.close();

         PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                 new X500Principal("CN=Test certificate Dia, C=UA"), pair.getPublic());
         JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
         ContentSigner signer = csBuilder.build(pair.getPrivate());
         PKCS10CertificationRequest csr = p10Builder.build(signer);

         writeByteArrayToFile(new File("melsahchenko.csr"), csr.getEncoded());
     }
}
