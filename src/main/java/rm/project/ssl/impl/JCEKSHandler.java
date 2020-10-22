package rm.project.ssl.impl;

import rm.project.ssl.KeyCertHandler;

import javax.crypto.KeyGenerator;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;

/**
 * JCEKS是Java平臺的一個金鑰庫格式,將金鑰儲存在金鑰庫中以防止加密金鑰的暴露。
 * 在JCEKS中儲存和裝載不同條目的過程類似於JKS,只需在呼叫KeyStore.getInstance()時更改相應的JCEKS金鑰庫型別。
 *
 * @author Klyve.Chen
 * @version 創建時間: 2020-10-22
 * @description
 */
public class JCEKSHandler implements KeyCertHandler {

    @Override
    public void createKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(null, null);
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(56);
            ;
            Key key = keyGen.generateKey();
            keyStore.setKeyEntry("secret", key, "password".toCharArray(), null);
            keyStore.store(new FileOutputStream("output.jceks"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    @Override
    public void storePrivateKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(null, null);
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(56);
            ;
            Key key = keyGen.generateKey();
            keyStore.setKeyEntry("secret", key, "password".toCharArray(), null);
            keyStore.store(new FileOutputStream("output.jceks"), "password".toCharArray());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    @Override
    public void storeCertificate() {

    }

    @Override
    public void loadPrivateKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream("output.jceks"), "password".toCharArray());
            Key key = keyStore.getKey("secret", "password".toCharArray());
            System.out.println(key.toString());
        } catch (Exception ex) { ex.printStackTrace();}
    }

    @Override
    public void loadCertificate() {

    }
}
