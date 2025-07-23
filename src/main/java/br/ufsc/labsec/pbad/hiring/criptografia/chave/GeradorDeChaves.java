package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import br.ufsc.labsec.pbad.hiring.Constantes;

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
        try {
            this.generator = KeyPairGenerator.getInstance(this.algoritmo, "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("Erro: O algoritmo de chave '" + this.algoritmo + "' não é válido ou não foi encontrado.", e);
        } catch (NoSuchProviderException e) {
            throw new NoSuchProviderException("Erro: O provedor de segurança 'BC' (Bouncy Castle) não foi encontrado.");
        }
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
        try {
            this.generator = KeyPairGenerator.getInstance(this.algoritmo, "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("Erro: " + this.algoritmo + " não é reconhecido como algorítmo válido", e);
        } catch (NoSuchProviderException e) {
            throw new NoSuchProviderException("Erro:  BC não é um provedor válido");
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

