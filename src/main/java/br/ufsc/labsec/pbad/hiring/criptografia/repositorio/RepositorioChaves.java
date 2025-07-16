package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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
        // TODO implementar
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     */
    public void abrir(String caminhoRepositorio) {
        // TODO implementar
    }

    /**
     * Obtém a chave privada do PKCS#12.
     *
     * @return Chave privada.
     */
    public PrivateKey pegarChavePrivada() {
        // TODO implementar
        return null;
    }

    /**
     * Obtém do certificado do PKCS#12.
     *
     * @return Certificado.
     */
    public X509Certificate pegarCertificado() {
        // TODO implementar
        return null;
    }

}
