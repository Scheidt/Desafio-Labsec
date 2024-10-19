package br.ufsc.labsec.utils;

import br.ufsc.labsec.Main;
import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.ConnectTimeoutException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

public class ConnectionUtils {
    private static Timeout TIMEOUT = Timeout.ofSeconds(5);

    /**
     * Realiza uma requisição GET a uma URI
     * @param uri A URI
     * @return O InputStream da resposta
     */
    public static InputStream get(URI uri) {
        HttpGet httpGet = new HttpGet(uri);
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(TIMEOUT)
                .setCookieSpec(StandardCookieSpec.STRICT)
                .build();

        PoolingHttpClientConnectionManager cm = getPoolingHttpClientConnectionManager();

        byte[] response = new byte[0];
        // redirects are automatically honoured (301, 302 and 307 codes)
        try (CloseableHttpClient client = HttpClientBuilder.create()
                .setRetryStrategy(new DefaultHttpRequestRetryStrategy())
                .setDefaultRequestConfig(requestConfig)
                .setConnectionManager(cm)
                .build()) {

            response = client.execute(httpGet, ConnectionUtils::responseToByteArray);

        } catch (SocketTimeoutException e) {
            Main.logger.log(Level.WARNING, "Timeout ao tentar baixar %s".formatted(uri.toString()), e);
        } catch (ClientProtocolException e) {
            Main.logger.log(Level.WARNING, "Erro de protocolo ao tentar baixar %s".formatted(uri.toString()), e);
        } catch (SocketException e) {
            Main.logger.log(Level.WARNING, "Erro de socket ao tentar baixar %s".formatted(uri.toString()), e);
        } catch (IOException e) {
            Main.logger.log(Level.WARNING, "Erro de I/O ao tentar baixar %s".formatted(uri.toString()), e);
        }

        return new ByteArrayInputStream(response);
    }

    private static PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager() {
        // files are usually signed and public, no need for HTTPS
        SSLContext allowAllHttps = null;
        try {
            allowAllHttps = SSLContexts.custom()
                    .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                    .build();
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            // if for some reason the context is null the default TLS factory will be used
            Main.logger.log(Level.WARNING, "Could not create SSL context", e);
        }

        SSLConnectionSocketFactory sslConfig = SSLConnectionSocketFactoryBuilder.create()
                .setSslContext(allowAllHttps)
                .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();

        ConnectionConfig cc = ConnectionConfig.custom()
                .setConnectTimeout(TIMEOUT)
                .setSocketTimeout(TIMEOUT)
                .setTimeToLive(TIMEOUT.toSeconds(), TimeUnit.SECONDS)
                .build();

        PoolingHttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslConfig)
                .setConnectionConfigResolver(c -> cc)
                .build();
        return cm;
    }

    private static byte[] responseToByteArray(ClassicHttpResponse response) throws IOException {
        HttpEntity responseEntity = response.getEntity();
        if (response.getCode() == HttpStatus.SC_NOT_FOUND) {
            throw new IOException();
        }
        return responseEntity.getContent().readAllBytes();    }
}
