package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import br.ufsc.labsec.pbad.hiring.Constantes;

/**
 * Essa classe representa um repositório de chaves do tipo PKCS#12.
 *
 * @see KeyStore
 */
public class RepositorioChaves {

    private KeyStore repositorio;
    private char[] senha;
    private String alias;

    /**
     * Construtor.
     *
     * @throws KeyStoreException       se o tipo de repositório não for suportado.
     * @throws NoSuchProviderException se o provedor "BC" não for encontrado.
     */
    public RepositorioChaves() throws KeyStoreException, NoSuchProviderException {
        try {
            this.repositorio = KeyStore.getInstance(Constantes.formatoRepositorio, "BC");
        } catch (KeyStoreException e) {
                throw new KeyStoreException("Erro ao instanciar RopositorioDeChave com algoritmo PKCS#12 ", e);
        } catch (NoSuchProviderException e) {
            throw new NoSuchProviderException("Erro: Não foi encontrado o provedor Bouncy Castle em RepositorioChaves ");
        }
    }

    /**
     * Construtor.
     *
     * @param algoritmo argumento optativo que permite modificar o tipo de algoritmo da KeyStore
     * @throws KeyStoreException       se o tipo de repositório não for suportado.
     * @throws NoSuchProviderException se o provedor "BC" não for encontrado.
     */
    public RepositorioChaves(String algoritmo) throws KeyStoreException, NoSuchProviderException {
        try {
            this.repositorio = KeyStore.getInstance(algoritmo, "BC");
        } catch (KeyStoreException e) {
            throw new KeyStoreException("Erro ao instanciar RopositorioDeChave com algoritmo: " + algoritmo, e);
        } catch (NoSuchProviderException e) {
            throw new NoSuchProviderException("Erro: Não foi encontrado o provedor Bouncy Castle em RepositorioChaves.");
        }
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     * @param senha              senha deste repositório de chaves
     * @throws KeyStoreException        se o repositório estiver vazio ou ocorrer outro erro de repositório.
     * @throws IOException              se houver um erro de I/O ao ler o arquivo.
     * @throws NoSuchAlgorithmException se o algoritmo de verificação de integridade não for encontrado.
     * @throws CertificateException     se houver um erro com os certificados no repositório.
     */
    public void abrir(String caminhoRepositorio, char[] senha) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        this.senha = senha;

        try (FileInputStream fileInputStream = new FileInputStream(caminhoRepositorio)) {
            // Carrega o keystore do arquivo usando a senha fornecida.
            this.repositorio.load(fileInputStream, this.senha);
        } catch (FileNotFoundException e) {
            throw new IOException("Erro com o caminho: " + caminhoRepositorio, e);
        } catch (IOException e) {
            throw new IOException("Erro ao carregar o repositório com chave em Repositorio Chaves", e);
        }

        Enumeration<String> aliases = this.repositorio.aliases();
        if (aliases.hasMoreElements()) {
            this.alias = aliases.nextElement();
        } else {
            throw new KeyStoreException("Erro: O repositório em '" + caminhoRepositorio + "' está vazio.");
        }
    }

    /**
     * Obtém a chave privada do PKCS#12.
     *
     * @return Chave privada.
     * @throws NullPointerException      se o repositório não foi aberto.
     * @throws KeyStoreException         se a entrada não for uma chave.
     * @throws NoSuchAlgorithmException  se o algoritmo para recuperar a chave não for encontrado.
     * @throws UnrecoverableKeyException se a chave não puder ser recuperada (e.g., senha errada).
     */
    public PrivateKey pegarChavePrivada() throws NullPointerException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (this.alias == null) {
            throw new NullPointerException("Erro: O repositório não foi aberto ou está vazio. Chame o método 'abrir' primeiro.");
        }
        try {
            return (PrivateKey) this.repositorio.getKey(this.alias, this.senha);
        } catch (UnrecoverableKeyException e) {
            throw new UnrecoverableKeyException("Erro: Verifique novamente a senha de '" + this.alias + "', pois não foi possível recuperar a chave.");
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new KeyStoreException("Erro ao tentar extrair a chave privada para o alias: " + this.alias, e);
        }
    }

    /**
     * Obtém do certificado do PKCS#12.
     *
     * @return Certificado.
     * @throws NullPointerException se o repositório não foi aberto.
     * @throws KeyStoreException    se a entrada correspondente ao alias não existir ou não for um certificado.
     */
    public X509Certificate pegarCertificado() throws NullPointerException, KeyStoreException {
        if (this.alias == null) {
            throw new NullPointerException("Erro: O repositório não foi aberto ou está vazio. Chame o método 'abrir' primeiro.");
        }
        try {
            return (X509Certificate) this.repositorio.getCertificate(this.alias);
        } catch (KeyStoreException e) {
            throw new KeyStoreException("Erro: Não foi possível pegar o certificado do repositório: " + this.alias, e);
        }
    }

}
