package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;

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

    /**
     * Construtor, caso não receber nenhum argumento, utiliza como default o algorítmo do arquivo de constantes.
     */

    public GeradorDeChaves() {
        this.algoritmo = Constantes.algoritmoChave;
        try {
            KeyPairGenerator.getInstance(this.algoritmo);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(this.algoritmo + " não é reconhecido como algorítmo válido");
            e.printStackTrace();
        }
    }

    /**
     * Construtor com argumento opcional, este argumento sobrescreve o algorítmo utilizado como padrão.
     *
     * @param algoritmo algoritmo de criptografia assimétrica a ser usado.
     */

    public GeradorDeChaves(String algoritmo) {
        this.algoritmo = algoritmo;
        try {
            KeyPairGenerator.getInstance(this.algoritmo);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(this.algoritmo + " não é reconhecido como algorítmo válido");
            e.printStackTrace();
        }
    }


    public GeradorDeChaves(String algoritmo) {
        this.algoritmo = algoritmo;
        try {
            KeyPairGenerator.getInstance(this.algoritmo);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(this.algoritmo + " não é reconhecido como algorítmo válido");
            e.printStackTrace();
        }
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
