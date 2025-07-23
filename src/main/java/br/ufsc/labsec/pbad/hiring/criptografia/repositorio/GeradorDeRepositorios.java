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
        gerarPkcs12(chavePrivada, certificado, caminhoPkcs12, alias, senha, Constantes.formatoRepositorio);
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
        KeyStore pkcs12KeyStore;
        try {
            pkcs12KeyStore = KeyStore.getInstance(algoritmo, "BC");
            pkcs12KeyStore.load(null, null);
        } catch (KeyStoreException e) {
            throw new KeyStoreException("Erro: O formato de repositório '" + algoritmo + "' não é suportado.", e);
        } catch (NoSuchProviderException e) {
            throw new NoSuchProviderException("O provedor de segurança 'BC' não foi encontrado.");
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IOException("Erro ao inicializar um repositório do tipo '" + algoritmo + "' vazio.", e);
        }

        try {
            // Coloca a chave no keystore
            pkcs12KeyStore.setKeyEntry(alias, chavePrivada, senha, new java.security.cert.Certificate[]{certificado});
        } catch (KeyStoreException e) {
            throw new KeyStoreException("Erro ao inserir a chave e o certificado no repositório com o alias '" + alias + "'.", e);
        }

        // Grava em disco
        try (FileOutputStream fileOutputStream = new FileOutputStream(caminhoPkcs12)) {
            pkcs12KeyStore.store(fileOutputStream, senha);
            System.out.println("    Repositório " + algoritmo + " escrito em disco com sucesso.");
        } catch (IOException e) {
            throw new IOException("Eroo ao escrever o arquivo de repositório em: " + caminhoPkcs12, e);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("Erro ao finalizar e salvar o repositório no arquivo: " + caminhoPkcs12, e);
        }
    }

}