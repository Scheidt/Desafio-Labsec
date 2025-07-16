package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

/**
 * Classe responsável por ler uma chave assimétrica do disco.
 *
 * @see KeyFactory
 * @see KeySpec
 */
public class LeitorDeChaves {

    /**
     * Lê a chave privada do local indicado.
     *
     * @param caminhoChave local do arquivo da chave privada.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave privada.
     */
    public static PrivateKey lerChavePrivadaDoDisco(String caminhoChave,
                                                    String algoritmo) {
        // TODO implementar
        return null;
    }

    /**
     * Lê a chave pública do local indicado.
     *
     * @param caminhoChave local do arquivo da chave pública.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave pública.
     */
    public static PublicKey lerChavePublicaDoDisco(String caminhoChave,
                                                   String algoritmo) {
        // TODO implementar
        return null;
    }

}
