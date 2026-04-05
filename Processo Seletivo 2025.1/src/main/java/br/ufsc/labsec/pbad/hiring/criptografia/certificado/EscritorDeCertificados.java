package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * Classe responsável por escrever um certificado no disco.
 */
public class EscritorDeCertificados {

    /**
     * Escreve o certificado indicado no disco.
     *
     * @param nomeArquivo           caminho que será escrito o certificado.
     * @param certificadoCodificado bytes do certificado.
     * @throws IOException caso ocorra um erro ao escrever o arquivo no disco.
     */
    public static void escreveCertificado(String nomeArquivo,
                                          byte[] certificadoCodificado) throws IOException {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(nomeArquivo))) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(certificadoCodificado));

            pemWriter.writeObject(certificate);

            System.out.println("     Certificado escrito em disco com sucesso");
        } catch (CertificateException e) {
            throw new IOException("Erro ao decodificar os bytes do certificado.", e);
        } catch (IOException e) {
            throw new IOException("Erro ao escrever o arquivo de certificado no caminho: " + nomeArquivo, e);
        }
    }

}
