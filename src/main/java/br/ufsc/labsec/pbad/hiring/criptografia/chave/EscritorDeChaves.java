package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
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
        Path caminhoOutput = Paths.get(nomeDoArquivo);
        if (caminhoOutput.getParent() != null) {
            Files.createDirectories(caminhoOutput.getParent());
        }

        String tipoPem = (chave.getFormat().equals("PKCS#8")) ? "PRIVATE KEY" : "PUBLIC KEY";
        PemObject pemObject = new PemObject(tipoPem, chave.getEncoded());

        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(nomeDoArquivo))) {
            pemWriter.writeObject(pemObject);
        }
    }
}
