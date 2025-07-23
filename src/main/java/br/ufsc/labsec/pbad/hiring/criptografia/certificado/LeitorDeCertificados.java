package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance(Constantes.formatoCertificado);
        } catch (CertificateException e) {
            throw new CertificateException("Erro: O formato de certificado '" + Constantes.formatoCertificado + "' não é reconhecido como um dormato válido.", e);
        }

        try (FileInputStream is = new FileInputStream(caminhoCertificado)) {
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
            System.out.println("    Certificado lido de disco com sucesso");
            return cert;
        } catch (FileNotFoundException e) {
            throw new IOException("Erro: Não encontrado arquivo de certificado  no caminho: " + caminhoCertificado, e);
        } catch (CertificateException e) {
            throw new CertificateException("Erro: Falha ao coletar os dados do certificado no arquivo: " + caminhoCertificado, e);
        }
    }

}
