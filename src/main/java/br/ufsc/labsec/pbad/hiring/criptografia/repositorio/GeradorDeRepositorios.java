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
     *                      comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     */
    public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha) {
        try {

            KeyStore pkcs12KeyStore = KeyStore.getInstance(Constantes.formatoRepositorio, "BC");

            try {
                pkcs12KeyStore.load(null, null);
            } catch (IOException e) {
                System.err.println("Erro ao carregar Keystore pkcs12KeyStore: " + e.getMessage());
                e.printStackTrace();
            }

            // Coloca a chave no Keystore
            pkcs12KeyStore.setKeyEntry(alias, chavePrivada, senha, new java.security.cert.Certificate[]{certificado});

            // Gravar em disco
            try (FileOutputStream fileOutputStream = new FileOutputStream(caminhoPkcs12)) {
                pkcs12KeyStore.store(fileOutputStream, senha);
                System.err.println("    Sucesso em GeradorDeRepositorios.java");
            } catch (IOException e) {
                System.err.println("Erro ao salvar Keystore em disco: " + e.getMessage());
                e.printStackTrace();
            }

        } catch (KeyStoreException e) {
            System.err.println("Erro ao instanciar a Keystore: " + e.getMessage());
            e.printStackTrace();

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erro ao instanciar a Keystore: " + e.getMessage());
            e.printStackTrace();

        } catch (CertificateException e) {
            System.err.println("Erro ao instanciar a Keystore: " + e.getMessage());
            e.printStackTrace();

        } catch (NoSuchProviderException e) {
            System.err.println("Não foi encontrado o provedor Bouncy Castle em GeradorDeRepositorios " + e.getMessage());
            e.printStackTrace();
        }

    }

    /**
     * Gera um PKCS#12 para a chave privada/certificado passados como parâmetro.
     *
     * @param chavePrivada  chave privada do titular do certificado.
     * @param certificado   certificado do titular.
     * @param caminhoPkcs12 caminho onde será escrito o PKCS#12.
     * @param alias         nome amigável dado à entrada do PKCS#12, que
     *                      comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     * @param algoritmo     algoritmo utilizado (padrão PKCS#12)
     */
    public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha, String algoritmo) {
        try {

            KeyStore pkcs12KeyStore = KeyStore.getInstance(algoritmo, "BC");

            try {
                pkcs12KeyStore.load(null, null);
            } catch (IOException e) {
                System.err.println("Erro ao carregar Keystore pkcs12KeyStore: " + e.getMessage());
                e.printStackTrace();
            }

            // Coloca a chave no Keystore
            pkcs12KeyStore.setKeyEntry(alias, chavePrivada, senha, new java.security.cert.Certificate[]{certificado});

            // Gravar em disco
            try (FileOutputStream fileOutputStream = new FileOutputStream(caminhoPkcs12)) {
                pkcs12KeyStore.store(fileOutputStream, senha);
                System.err.println("    Sucesso em GeradorDeRepositorios.java com algoritmo " + algoritmo);
            } catch (IOException e) {
                System.err.println("Erro ao salvar Keystore em disco: " + e.getMessage());
                e.printStackTrace();
            }

        } catch (KeyStoreException e) {
            System.err.println("Erro ao instanciar a Keystore com algoritmo: " + algoritmo + "\n" + e.getMessage());
            e.printStackTrace();

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erro ao instanciar a Keystore: " + e.getMessage());
            e.printStackTrace();

        } catch (CertificateException e) {
            System.err.println("Erro ao instanciar a Keystore: " + e.getMessage());
            e.printStackTrace();

        } catch (NoSuchProviderException e) {
            System.err.println("Não foi encontrado o provedor Bouncy Castle em GeradorDeRepositorios " + e.getMessage());
            e.printStackTrace();
        }

    }

}
