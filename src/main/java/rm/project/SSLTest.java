package rm.project;

import javax.crypto.KeyGenerator;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;

/**
 * 收錄: https://www.itread01.com/p/304925.html
 * 金鑰庫是一個存放加密金鑰和證書的儲存設施,
 * 它們經常用於SSL通訊來標明伺服器和客戶機的身份,
 * 一個金鑰庫可以是一份檔案或硬體裝置。
 * Java中不同型別的金鑰庫包含: PrivateKey、SecretKey、JKS、PKCS12、JCEKS等。
 * 其中JKS的詳細介紹可參考《Java不同金鑰庫型別之JKS》。
 * 本文所講訴的為PKCS12和JCEKS的用法
 *
 * @author Klyve.Chen
 * @version 創建時間: 2020-10-21
 * @description
 */
public class SSLTest {

    public static void main(String[] args) {
    }

    private static void testJCEKS() {
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

}
