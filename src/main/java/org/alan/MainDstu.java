package org.alan;

import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
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
import java.math.BigInteger;
import java.security.*;

import static org.apache.commons.io.FileUtils.writeByteArrayToFile;

public class MainDstu {
     public static void main(String[] args) throws OperatorCreationException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, InvalidKeyException, SignatureException {
         Security.addProvider(new BouncyCastleProvider());

         // ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
         ECDomainParameters ecDP = DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.2"));
         ECCurve curve = ecDP.getCurve();

         // NOTE: For some reason this test uses an alternate base-point to the registry curve
         ecDP = new ECDomainParameters(curve,
                 curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16)),
                 ecDP.getN(), ecDP.getH(), ecDP.getSeed());

         DSTU4145ParameterSpec spec = new DSTU4145ParameterSpec(ecDP);

         KeyPairGenerator g = KeyPairGenerator.getInstance("DSTU4145", "BC");
         g.initialize(spec, new SecureRandom());
         KeyPair pair = g.generateKeyPair();

         JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_128_CBC);
         encryptorBuilder.setRandom(new SecureRandom());
         encryptorBuilder.setPasssword("123456".toCharArray());
         OutputEncryptor encryptor = encryptorBuilder.build();

         JcaPKCS8Generator pkcs8 = new JcaPKCS8Generator(pair.getPrivate(), encryptor );
         JcaPEMWriter privateKeyWriter = new JcaPEMWriter(new FileWriter("dstu-mel-private.pem"));
         PemObject pemkey = pkcs8.generate();
         privateKeyWriter.writeObject(pemkey);
         privateKeyWriter.close();

         PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                 new X500Principal("CN=Mel DSTU Test, C=UA"), pair.getPublic());
         JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("GOST34311withDSTU4145");
         ContentSigner signer = csBuilder.build(pair.getPrivate());
         PKCS10CertificationRequest csr = p10Builder.build(signer);

         // test keys
         Signature signatureProvcider = Signature.getInstance("GOST34311withDSTU4145", BouncyCastleProvider.PROVIDER_NAME);

         // sign
         signatureProvcider.initSign(pair.getPrivate());
         signatureProvcider.update("test".getBytes());
         byte[] signature = signatureProvcider.sign();


         // verify
         signatureProvcider.initVerify(pair.getPublic());
         signatureProvcider.update("test".getBytes());
         boolean verify = signatureProvcider.verify(signature);

         System.out.printf("Signature is %s", verify);

         if(verify) {
             writeByteArrayToFile(new File("mel-dstu.csr"), csr.getEncoded());

             writeByteArrayToFile(new File("priv-dstu.dat"), pair.getPrivate().getEncoded());
             writeByteArrayToFile(new File("pub-dstu.dat"), pair.getPublic().getEncoded());

         }else{
             throw new Error("Invalid signature");
         }
     }
}
/*
* private void CreatePfxFile(X509Certificate certificate, AsymmetricKeyParameter privateKey)
{
    // create certificate entry
    var certEntry = new X509CertificateEntry(certificate);
    string friendlyName = certificate.SubjectDN.ToString();

    // get bytes of private key.
    PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
    byte[] keyBytes = keyInfo.ToAsn1Object().GetEncoded();

    var builder = new Pkcs12StoreBuilder();
    builder.SetUseDerEncoding(true);
    var store = builder.Build();

    // create store entry
    store.SetKeyEntry(Core.Constants.PrivateKeyAlias, new AsymmetricKeyEntry(privateKey), new X509CertificateEntry[] { certEntry });

    byte[] pfxBytes = null;

    var password = Guid.NewGuid().ToString("N");

    using (MemoryStream stream = new MemoryStream())
    {
        store.Save(stream, password.ToCharArray(), new SecureRandom());
        pfxBytes = stream.ToArray();
    }

    var result = Pkcs12Utilities.ConvertToDefiniteLength(pfxBytes);
    this.StoreCertificate(Convert.ToBase64String(result));
}
* */