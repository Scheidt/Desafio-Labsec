package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
     */
    public RepositorioChaves() {
        try {
            this.repositorio = KeyStore.getInstance(Constantes.formatoRepositorio, "BC");
        } catch (KeyStoreException e) {
                System.err.println("Erro ao instanciar RopositorioDeChave com algoritmo PKCS#12 " + "\n" + e.getMessage());
                e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.err.println("Não foi encontrado o provedor Bouncy Castle em RepositorioChaves " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Construtor.
     * 
     * @param algoritmo argumento optativo que permite modificar o tipo de algoritmo da KeyStore
     */
    public RepositorioChaves(String algoritmo) {
        try {
            this.repositorio = KeyStore.getInstance(algoritmo, "BC");
        } catch (KeyStoreException e) {
            System.err.println("Erro ao instanciar RopositorioDeChave com algoritmo: " + algoritmo + "\n" + e.getMessage());
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.err.println("Não foi encontrado o provedor Bouncy Castle em RepositorioChaves " + e.getMessage());
            e.printStackTrace();
        } 
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     * @param senha senha deste repositório de chaves
     */
    public void abrir(String caminhoRepositorio, char[] senha) throws KeyStoreException {
        this.senha = senha;

        try (FileInputStream fileInputStream = new FileInputStream(caminhoRepositorio)) {
            // Carrega o keystore do arquivo usando a senha fornecida.
            this.repositorio.load(fileInputStream, this.senha);

            // Pega o primeiro certificado da KeyStore
            Enumeration<String> aliases = this.repositorio.aliases();
            if (aliases.hasMoreElements()) {
                this.alias = aliases.nextElement();
            } else {
                throw new KeyStoreException("O repositório de chaves está vazio");
            }

        } catch (IOException e) {
            System.err.println("Erro com o caminho: " + caminhoRepositorio + "\n" + e.getMessage());
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e){
            System.err.println("Erro ao carregar o repositório com chave"  + "\n" + e.getMessage());
            e.printStackTrace();

        } catch (CertificateException e) {

        } catch (KeyStoreException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Obtém a chave privada do PKCS#12.
     *
     * @return Chave privada.
     */
    public PrivateKey pegarChavePrivada() throws NullPointerException {
        if (this.alias == null) {
            throw new NullPointerException("O repositório não foi aberto ou está vazio. Chame o método 'abrir' primeiro.");
        }
        try {
            // Extrai a chave usando o alias e a senha.
            PrivateKey chavePrivada = (PrivateKey) this.repositorio.getKey(this.alias, this.senha);
            return chavePrivada;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.err.println("Não foi possível pegar a chave privada do repositório. " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Obtém do certificado do PKCS#12.
     *
     * @return Certificado.
     */
    public X509Certificate pegarCertificado() {
        if (this.alias == null) {
            throw new NullPointerException("O repositório não foi aberto ou está vazio. Chame o método 'abrir' primeiro.");
        }
        try {
            // Extrai a chave usando o alias e a senha.
            X509Certificate chavePublica = (X509Certificate) this.repositorio.getCertificate(this.alias);
            return chavePublica;
        } catch (KeyStoreException e) {
            System.err.println("Não foi possível pegar o certificado do repositório. " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

}
