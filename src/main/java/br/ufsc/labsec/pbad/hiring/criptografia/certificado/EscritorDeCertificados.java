package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.FileWriter;
import java.io.IOException;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Classe responsável por escrever um certificado no disco.
 */
public class EscritorDeCertificados {

    /**
     * Escreve o certificado indicado no disco.
     *
     * @param nomeArquivo           caminho que será escrito o certificado.
     * @param certificadoCodificado bytes do certificado.
     */
    public static void escreveCertificado(String nomeArquivo,
                                          byte[] certificadoCodificado) {
        try (PemWriter pemWriter = new PemWriter(new FileWriter(nomeArquivo))) {
            PemObject pemObject = new PemObject("CERTIFICATE", certificadoCodificado);
            pemWriter.writeObject(pemObject);
            System.err.println("    Sucesso ao escrever o certificado em disco (formato PEM)");
        } catch (IOException e) {
            System.err.println("Falha ao escrever o certificado no caminho: " + nomeArquivo);
            e.printStackTrace();
        }
    }

}
