package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por ler um certificado do disco.
 *
 * @see CertificateFactory
 */
public class LeitorDeCertificados {

    /**
     * Lê um certificado do local indicado.
     *
     * @param caminhoCertificado caminho do certificado a ser lido.
     * @return Objeto do certificado.
     * @throws CertificateException caso ocorra um erro ao inicializar a fábrica de certificados ou ao gerar o certificado.
     * @throws IOException          caso o arquivo de certificado não seja encontrado ou ocorra um erro de leitura.
     */
    public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado) throws CertificateException, IOException {
        CertificateFactory certFactory = CertificateFactory.getInstance(Constantes.formatoCertificado);
        try (FileInputStream is = new FileInputStream(caminhoCertificado)) {
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
            System.out.println("    Certificado lido de disco com sucesso");
            return cert;
        }
    }

}