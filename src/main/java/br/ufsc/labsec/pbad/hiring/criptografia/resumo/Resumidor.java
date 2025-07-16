package br.ufsc.labsec.pbad.hiring.criptografia.resumo;

import java.io.File;
import java.security.MessageDigest;

/**
 * Classe responsável por executar a função de resumo criptográfico.
 *
 * @see MessageDigest
 */
public class Resumidor {

    private MessageDigest md;
    private String algoritmo;

    /**
     * Construtor.
     */
    public Resumidor() {
        // TODO implementar
    }

    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param arquivoDeEntrada arquivo a ser processado.
     * @return Bytes do resumo.
     */
    public byte[] resumir(File arquivoDeEntrada) {
        // TODO implementar
        return null;
    }

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) {
        // TODO implementar
    }

}
