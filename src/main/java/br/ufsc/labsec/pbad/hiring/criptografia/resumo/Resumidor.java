package br.ufsc.labsec.pbad.hiring.criptografia.resumo;


import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;


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
    public Resumidor() throws NoSuchAlgorithmException {
        this.algoritmo = Constantes.algoritmoResumo;
        try {
            this.md = MessageDigest.getInstance(this.algoritmo);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("Erro: Não foi reconhecido algoritmo: " + this.algoritmo, e);
        }
    }

    /**
     * Constructor com parâmetro optativo para outro algorítmo
     * @param algoritmo string com o nome do algoritmo utilizado
     */

    public Resumidor(String algoritmo) throws NoSuchAlgorithmException {
        this.algoritmo = algoritmo;
        try {
            this.md = MessageDigest.getInstance(this.algoritmo);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("Erro: Não foi reconhecido algoritmo: " + this.algoritmo, e);
        }
    }


    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param caminhoTexto caminho do arquivo a ser processado.
     * @return Bytes do resumo.
     */
    public byte[] resumir(Path caminhoTexto) throws IOException {
        try {
            byte[] textoBytes = Files.readAllBytes(caminhoTexto);
            return md.digest(textoBytes);
        } catch (IOException e) {
            throw new IOException("Erro com o caminho: " + caminhoTexto, e);
        }
    }

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, Path caminhoArquivo) throws IOException {
        HexFormat formatadorHex = HexFormat.of();
        String resumoHex = formatadorHex.formatHex(resumo);

        try {
            Files.createDirectories(caminhoArquivo.getParent());
            Files.write(caminhoArquivo, resumoHex.getBytes());
        } catch (IOException e) {
            throw new IOException("Erro no caminho: " + caminhoArquivo, e);
        }
    }

}
