package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

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
     * @throws IOException caso ocorra um erro ao escrever o arquivo no disco.
     */
    public static void escreveChaveEmDisco(Key chave, String nomeDoArquivo) throws IOException {
        try {
            Path caminhoOutput = Paths.get(nomeDoArquivo);
            if (caminhoOutput.getParent() != null) {
                Files.createDirectories(caminhoOutput.getParent());
            }

            final String tipoPem;
            if (chave instanceof PrivateKey) {
                tipoPem = "PRIVATE KEY";
            } else if (chave instanceof PublicKey) {
                tipoPem = "PUBLIC KEY";
            } else {
                throw new IllegalArgumentException("A chave fornecida não é uma chave pública ou privada reconhecida.");
            }
            
            PemObject pemObject = new PemObject(tipoPem, chave.getEncoded());

            try (Writer fileWriter = Files.newBufferedWriter(caminhoOutput, StandardCharsets.UTF_8);
                 JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter)) {
                pemWriter.writeObject(pemObject);
            }
            
        } catch (IOException e) {
            throw new IOException("Erro ao escrever a chave PEM em: " + nomeDoArquivo, e);
        } catch (IllegalArgumentException e) {
            throw new IOException("Erro ao tentar interpretar a chave fornecida: " + e.getMessage(), e);
        }
    }
}