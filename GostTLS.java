import ru.CryptoPro.JCP.JCP;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.UUID;

import javax.net.ssl.*;

public class HttpTLSGost {
    private String keyStoreType = JCP.HD_STORE_NAME;
    private char[] keyStorePassword= "changeit".toCharArray();

    private String trusstStoreAlias = JCP.HD_STORE_NAME;
    private String trusstStoreType = JCP.HD_STORE_NAME;
    private char[] trusstStorePassword= "changeit".toCharArray();

    public void d() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        Security.setProperty("ssl.SocketFactory.provider","ru.CryptoPro.ssl.SSLSocketFactoryImpl");
        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");

       /* System.setProperty("javax.net.ssl.keyStoreType",ksType);
        System.setProperty("javax.net.ssl.keyStorePassword", ksPassword);

        System.setProperty("javax.net.ssl.trustStoreType",tsType);
        System.setProperty("javax.net.ssl.trustStore",tsAlias);
        System.setProperty("javax.net.ssl.trustStorePassword", tsPassword);*/

        SSLContext sslContext = SSLContext.getInstance("GostTLS");

        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, keyStorePassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("GostX509");
        kmf.init(keyStore, keyStorePassword);

        KeyStore trustedKeyStore = KeyStore.getInstance(trusstStoreType);
        trustedKeyStore.load(new FileInputStream(trusstStoreAlias), trusstStorePassword);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("GostX509");
        tmf.init(trustedKeyStore);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);


        URL url = new URL("http://www.oracle.com/");
       /* URLConnection yc = url.openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(
                yc.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null)
            System.out.println(inputLine);
        in.close();*/

        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }

    public SSLContext getSSLContext(Key key, java.security.cert.Certificate[] keyCertificates, ArrayList<java.security.cert.Certificate> certificates) throws Exception {
        String storeAlgorithm = "GostX509";
        String contextAlgorithm = "GostTLS"; //Provider.ALGORITHM
        String keyAlias = UUID.randomUUID().toString();
        String randomPass = UUID.randomUUID().toString();
        String trustAlias;
        SSLContext sslContext;
        KeyStore keyStore;
        KeyStore trustStore;
        KeyManagerFactory keyManagerFactory;
        TrustManagerFactory trustManagerFactory;

        keyStore = KeyStore.getInstance(JCP.MEMORY_STORE_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry(keyAlias, key, randomPass.toCharArray(), keyCertificates);
        keyStore.store(null, null);
        keyManagerFactory = KeyManagerFactory.getInstance(storeAlgorithm);
        keyManagerFactory.init(keyStore, randomPass.toCharArray());

        trustStore = KeyStore.getInstance(JCP.MEMORY_STORE_NAME);
        trustStore.load(null, null);
        for (Certificate certificate : certificates) {
            trustAlias = UUID.randomUUID().toString();
            trustStore.setCertificateEntry(trustAlias, certificate);
        }
        trustStore.store(null, null);
        trustManagerFactory = TrustManagerFactory.getInstance(storeAlgorithm);
        trustManagerFactory.init(trustStore);

        sslContext = SSLContext.getInstance(contextAlgorithm);
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        return sslContext;
    }
}
