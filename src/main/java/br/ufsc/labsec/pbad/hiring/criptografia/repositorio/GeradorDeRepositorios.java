package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por gerar um repositório de chaves PKCS#12.
 *
 * @see KeyStore
 */
public class GeradorDeRepositorios {

    /**
     * Gera um PKCS#12 para a chave privada/certificado passados como parâmetro.
     *
     * @param chavePrivada  chave privada do titular do certificado.
     * @param certificado   certificado do titular.
     * @param caminhoPkcs12 caminho onde será escrito o PKCS#12.
     * @param alias         nome amigável dado à entrada do PKCS#12, que
     * comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     * @throws KeyStoreException        em caso de erro com o tipo de repositório.
     * @throws NoSuchProviderException  se o provedor "BC" não for encontrado.
     * @throws IOException              em caso de erro de I/O ao carregar ou salvar o repositório.
     * @throws NoSuchAlgorithmException se o algoritmo para verificação de integridade do repositório não for encontrado.
     * @throws CertificateException     em caso de erro com o certificado.
     */
    public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha) throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore pkcs12KeyStore = KeyStore.getInstance(Constantes.formatoRepositorio, "BC");
        pkcs12KeyStore.load(null, null);

        // Coloca a chave no Keystore
        pkcs12KeyStore.setKeyEntry(alias, chavePrivada, senha, new java.security.cert.Certificate[]{certificado});

        // Grava em disco
        try (FileOutputStream fileOutputStream = new FileOutputStream(caminhoPkcs12)) {
            pkcs12KeyStore.store(fileOutputStream, senha);
            System.out.println("    Repositório PKCS#12 escrito em disco com sucesso.");
        }
    }

    /**
     * Gera um PKCS#12 para a chave privada/certificado passados como parâmetro.
     *
     * @param chavePrivada  chave privada do titular do certificado.
     * @param certificado   certificado do titular.
     * @param caminhoPkcs12 caminho onde será escrito o PKCS#12.
     * @param alias         nome amigável dado à entrada do PKCS#12, que
     * comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     * @param algoritmo     algoritmo utilizado (padrão PKCS#12)
     * @throws KeyStoreException        em caso de erro com o tipo de repositório.
     * @throws NoSuchProviderException  se o provedor "BC" não for encontrado.
     * @throws IOException              em caso de erro de I/O ao carregar ou salvar o repositório.
     * @throws NoSuchAlgorithmException se o algoritmo para verificação de integridade do repositório não for encontrado.
     * @throws CertificateException     em caso de erro com o certificado.
     */
    public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha, String algoritmo) throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore pkcs12KeyStore = KeyStore.getInstance(algoritmo, "BC");
        pkcs12KeyStore.load(null, null);

        // Coloca a chave no Keystore
        pkcs12KeyStore.setKeyEntry(alias, chavePrivada, senha, new java.security.cert.Certificate[]{certificado});

        // Grava em disco
        try (FileOutputStream fileOutputStream = new FileOutputStream(caminhoPkcs12)) {
            pkcs12KeyStore.store(fileOutputStream, senha);
            System.out.println("    Repositório " + algoritmo + " escrito em disco com sucesso.");
        }
    }

}
