package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.security.Key;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;

/**
 * Essa classe é responsável por escrever uma chave assimétrica no disco. Note
 * que a chave pode ser tanto uma chave pública quanto uma chave privada.
 *
 * @see Key
 */
public class EscritorDeChaves {

    /**
     * Escreve uma chave no local indicado.
     *
     * @param chave         chave assimétrica a ser escrita em disco.
     * @param nomeDoArquivo nome do local onde será escrita a chave.
     */
    public static void escreveChaveEmDisco(Key chave, String nomeDoArquivo) {
        try {
            Path caminhoOutput = Paths.get(nomeDoArquivo);
            if (caminhoOutput.getParent() != null) {
                Files.createDirectories(caminhoOutput.getParent());
            }

            Files.write(caminhoOutput, chave.getEncoded());

        } catch (IOException e) {.
            System.err.println("Erro ao escrever chave: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
