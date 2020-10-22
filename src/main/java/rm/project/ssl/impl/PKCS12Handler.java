package rm.project.ssl.impl;

import rm.project.ssl.KeyCertHandler;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.KeyGenerator;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * @author Klyve.Chen
 * @version 創建時間: 2020-10-21
 * @description
 */
public class PKCS12Handler implements KeyCertHandler {

    /**
     * 在把一個條目存入PKCS12之前必須先載入金鑰庫,這意味著我們必須首先建立一個金鑰庫。
     * 簡單建立一個PKCS12金鑰庫的方式如下:
     * 需要注意的是,在呼叫keyStore.load(null, null)時,
     * 兩個null是作為輸入金鑰流和密碼傳遞的。這是因為我們沒有可用的金鑰庫。執行這段程式碼後,當前工作目錄中應該會輸出一個名為output.p12的檔案。
     */
    public void createKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream("output.p12"), "password".toCharArray());
        } catch (Exception ex) {ex.printStackTrace();}
    }

    @Override
    public void loadPrivateKey() {

    }

    @Override
    public void storePrivateKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            Key key = keyGen.generateKey();
            keyStore.setKeyEntry("secret", key, "password".toCharArray(), null);
            keyStore.store(new FileOutputStream("output.p12"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    public void storePrivateKey2() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");//
            keyStore.load(new FileInputStream("output.p12"), "password".toCharArray());
            keyStore.load(null, null);
            ;
            CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
            gen.generate(1024);
            Key key = gen.getPrivateKey();
            X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = cert;
            keyStore.setKeyEntry("private", key, "password".toCharArray(), chain);
            keyStore.store(new FileOutputStream("output.p12"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    @Override
    public void loadCertificate() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("output.p12"), "password".toCharArray());
            java.security.cert.Certificate cert = keyStore.getCertificate("private");
            System.out.println(cert);
        } catch (Exception ex) { ex.printStackTrace();}
    }

    @Override
    public void storeCertificate() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");//
            keyStore.load(new FileInputStream("output.p12"), "password".toCharArray());
            keyStore.load(null, null);
            ;
            CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
            gen.generate(1024);
            X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);
            keyStore.setCertificateEntry("cert", cert);
            keyStore.store(new FileOutputStream("output.p12"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }
}
