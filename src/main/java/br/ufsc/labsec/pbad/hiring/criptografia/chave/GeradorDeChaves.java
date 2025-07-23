package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;

/**
 * Classe responsável por gerar pares de chaves assimétricas.
 *
 * @see KeyPair
 * @see PublicKey
 * @see PrivateKey
 */
public class GeradorDeChaves {

    private String algoritmo;
    private KeyPairGenerator generator;

    static {
        // Garante que o provedor Bouncy Castle esteja disponível
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

    }
    /**
     * Construtor, caso não receber nenhum argumento, utiliza como default o algorítmo do arquivo de constantes.
     *
     * @throws NoSuchAlgorithmException se o algoritmo não for reconhecido.
     * @throws NoSuchProviderException se o provedor "BC" não for encontrado.
     */

    public GeradorDeChaves() throws NoSuchAlgorithmException, NoSuchProviderException {
        this.algoritmo = Constantes.algoritmoChave;
        this.generator = KeyPairGenerator.getInstance(this.algoritmo, "BC");
    }

    /**
     * Construtor com argumento opcional, este argumento sobrescreve o algorítmo utilizado como padrão.
     *
     * @param algoritmo algoritmo de criptografia assimétrica a ser usado.
     * @throws NoSuchAlgorithmException se o algoritmo não for reconhecido.
     * @throws NoSuchProviderException se o provedor "BC" não for encontrado.
     */

    public GeradorDeChaves(String algoritmo) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.algoritmo = algoritmo;
        this.generator = KeyPairGenerator.getInstance(this.algoritmo, "BC");
    }

    /**
     * Gera um par de chaves, usando o algoritmo definido pela classe, com o
     * tamanho da chave especificado.
     *
     * @param tamanhoDaChave tamanho em bits das chaves geradas.
     * @return Par de chaves.
     * @see SecureRandom
     */
    public KeyPair gerarParDeChaves(int tamanhoDaChave) {
        this.generator.initialize(tamanhoDaChave);
        return this.generator.generateKeyPair();
    }

}
