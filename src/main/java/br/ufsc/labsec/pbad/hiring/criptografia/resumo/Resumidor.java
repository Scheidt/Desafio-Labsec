package br.ufsc.labsec.pbad.hiring.criptografia.resumo;


import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
    public Resumidor() {

        this.algoritmo = Constantes.algoritmoResumo;
        try {
            this.md = MessageDigest.getInstance(this.algoritmo);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Constructor com parâmetro optativo para outro algorítmo
     * @param algoritmo string com o nome do algoritmo utilizado
     */

    public Resumidor(String algoritmo){
        this.algoritmo = algoritmo;
        try {
            this.md = MessageDigest.getInstance(this.algoritmo);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(this.algoritmo + " não é reconhecido como algorítmo válido");
            e.printStackTrace();
        }
    }


    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param caminhoTexto caminho do arquivo a ser processado.
     * @return Bytes do resumo.
     */
    public byte[] resumir(Path caminhoTexto) {
        try {
            byte[] textoBytes = Files.readAllBytes(caminhoTexto);
            return md.digest(textoBytes);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, Path caminhoArquivo) {
        try {
            HexFormat formatadorHex = HexFormat.of();
            String resumoHex = formatadorHex.formatHex(resumo);

            Files.createDirectories(caminhoArquivo.getParent());

            Files.write(caminhoArquivo, resumoHex.getBytes());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
