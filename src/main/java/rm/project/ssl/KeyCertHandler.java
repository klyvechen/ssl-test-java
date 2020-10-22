package rm.project.ssl;

/**
 * JCEKS是Java平臺的一個金鑰庫格式,將金鑰儲存在金鑰庫中以防止加密金鑰的暴露。
 * 在JCEKS中儲存和裝載不同條目的過程類似於JKS,只需在呼叫KeyStore.getInstance()時更改相應的JCEKS金鑰庫型別。
 *
 * @author Klyve.Chen
 * @version 創建時間: 2020-10-22
 * @description
 */
public interface KeyCertHandler {

    void createKeyStore();

    void loadPrivateKey();

    void storePrivateKey();

    void loadCertificate();

    void storeCertificate();

}
