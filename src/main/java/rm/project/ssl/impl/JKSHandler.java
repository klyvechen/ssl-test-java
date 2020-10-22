package rm.project.ssl.impl;

import rm.project.ssl.KeyCertHandler;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * @author Klyve.Chen
 * @version 創建時間: 2020-10-21
 * @description
 */
public class JKSHandler implements KeyCertHandler {

    /**
     * Create JKS keystore
     * The simplest method to create a JKS keystore to create an empty keystore.
     * We can first get an instance of KeyStore and then load a null keystore.
     * After loading the null keystore,
     * we just need to call KeyStore.store() with the keystore name and password of the keystore.
     *
     */
    public void createKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream("mytestkey.jks"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    /**
     * Store private key
     * Now let's store one private key and its associated certificate chain into the keystore.
     * Note we can not store a private key without an associated certificate chain into a keystore using JDK.
     * With some other library or native libraries,
     * you may be able to store a private key without associated certificate chain.
     *
     * First, we will create a private key and a self signed certificate and then call KeyStore.setKeyEntry()
     * with the specified alias, key, the password for the key and its associated certificate chain.
     * Remember we need to call KeyStore.store() to store the key into the keystore.
     */
    public void storePrivateKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("mytestkey.jks"), "password".toCharArray());
            CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
            gen.generate(1024);
            Key key = gen.getPrivateKey();
            X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = cert;
            keyStore.setKeyEntry("mykey", key, "password".toCharArray(), chain);
            keyStore.store(new FileOutputStream("mytestkey.jks"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    /**
     * Store certificate
     * We can store certificate on JKS keystore.
     * The certificate to be store should be a X509Certificate.
     * It can be stored on the keystore without associated private key.
     * This process is similar to storing private key.
     *
     *
     */
    public void storeCertificate() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("mytestkey.jks"), "password".toCharArray());
            CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
            gen.generate(1024);
            X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=SINGLE_CERTIFICATE"), (long) 365 * 24 * 3600);
            keyStore.setCertificateEntry("single_cert", cert);
            keyStore.store(new FileOutputStream("mytestkey.jks"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    /**
     * Loading private key
     * After storing the keys, we can also load the entries inside the keystore.
     * Here we are saying to load private key, actually it's not the case here, as we described earlier,
     * the private key cannot be extracted from JKS using Java.
     * Here we actually extract the certificate chain of the private key.
     *
     * Note the commented line, the key will be null as expected. We can get the certificate chain as normal though.
     *
     * [[Version: V3Subject: CN=ROOTSignature Algorithm: SHA1withRSA,
     * OID = 1.2.840.113549.1.1.5Key:Sun RSA public key, 1024 bits
     * modulus: 90980299845597512779139009881469177009407272139633139241921529845092210461181243924599150259446249079941561941533303439718936138867375776965995893255358889228584415558006141961051402385279285497775776996780406808976543439543789816486513982581378223575354716191394304768315366544413052547926792470794374067383
     * public exponent: 65537
     * Validity: [From: Sat Sep 06 09:57:28 CST 2014, To: Sun Sep 06 09:57:28 CST 2015]
     * Issuer: CN=ROOTSerialNumber: [206b697b]]
     * Algorithm:
     * [SHA1withRSA]Signature:0000: 53 6A FD FE E6 3A 5E 6E A6 43 C4 F4 D1 56 D4 08Sj...:^n.C...V..0010: 7E 3B 8B 73 68 71 56 AB 96 FE 24 E7 2D DC 04 BB.;.shqV...$.-...0020: 14 B0 C6 71 8D F0 3E EC FE D8 5B BB 8C 0F 55 63...q..>...[...Uc0030: 2B 38 8E 45 F1 2D F0 BB 8C 6D 13 A8 11 37 E1 FA+8.E.-...m...7..0040: 77 AF C7 73 72 2B 40 4F 74 32 F6 3C 24 E6 AB EDw..sr+@Ot2.<$...0050: 2C 6F 19 2E DC 58 5F CB 75 62 40 2F 3E BE 59 99, o...X_.ub@/>.Y.0060: C0 1F 7A 70 15 AF C3 66 B3 4F C9 11 C3 45 59 EF..zp...f.O...EY.0070: 36 F4 1C C9 9B FA 5E 43 A0 28 DB 07 0D F2 53 6E6.....^C.(....Sn]
     */
    public void loadPrivateKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("mytestkey.jks"), "password".toCharArray());
            Key key = keyStore.getKey("alias", "password".toCharArray());
            System.out.println("Private key : " + key.toString());
            //You will get a NullPointerException if you uncomment this line
            Certificate[] chain = keyStore.getCertificateChain("mykey");
            for (Certificate cert : chain) {
                System.out.println(cert.toString());
            }
        } catch (Exception ex) { ex.printStackTrace();}
    }

    /**
     * Loading certificate
     * This is similar to loading private key, we need to pass the alias of the certificate we want to extract.
     *
     * The output will be:
     *
     * [[Version: V3Subject: CN=SINGLE_CERTIFICATE
     * Signature Algorithm: SHA1withRSA,
     * OID = 1.2.840.113549.1.1.5Key:Sun RSA public key, 1024 bits
     * modulus: 99756834215197288877309915243024788596281418171661241282881476656110879586349799740269767889529808199104172091786860877280382867461569439907754755558759387462421169749111354565793974372777424046360810758009149155148290676527032833774084635148674232352006810533640038723102562578516643345287042787777951043863
     * public exponent: 65537
     * Validity: [From: Sat Sep 06 10:14:33 CST 2014, To: Sun Sep 06 10:14:33 CST 2015]
     * Issuer: CN=SINGLE_CERTIFICATE
     * SerialNumber: [6943e549]]
     * Algorithm: [SHA1withRSA]
     * Signature:0000: 35 58 70 96 F4 35 82 2A 95 9F BB 31 02 6E 7C 295Xp..5.*...1.n.)0010: 4A FE AF EB 2D B5 3A A7 C7 9D 4C 9A 34 2C 5C 46J...-.:...L.4,/F0020: C2 82 A8 AC 1A C0 98 A5 67 21 74 7B 1E E2 E5 AC........g!t.....0030: DE B2 1D 87 BE 16 45 9B D0 2A D3 2B F6 E1 4B 35......E..*.+..K50040: 27 8B A7 0A EF F2 07 41 90 A6 69 07 BE 87 C5 B1'......A..i.....0050: 54 DE DB A2 5A 41 47 3B 3F A7 74 6F 5C C8 8D B4T...ZAG;?.to/...0060: C8 65 2B 0F 8E 94 A8 80 C7 8B B5 78 FA C2 9C ED.e+........x....0070: 8E EC 28 E4 8E 62 A1 59 6A BC 37 7B 0D FC C7 AF..(..b.Yj.7.....]
     */
    public void loadCertificate() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("mytestkey.jks"), "password".toCharArray());
            java.security.cert.Certificate cert = keyStore.getCertificate("single_cert");
            System.out.println(cert.toString());
        } catch (Exception ex) { ex.printStackTrace();}
    }
}
