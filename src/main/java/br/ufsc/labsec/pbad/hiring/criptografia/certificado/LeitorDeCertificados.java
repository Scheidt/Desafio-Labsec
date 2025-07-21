package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
     */
    public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado) {
        // função pesadamente inspirada em: https://stackoverflow.com/questions/50462304/how-to-read-information-from-ssl-certificate-file
        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance(Constantes.formatoCertificado);
            FileInputStream is = new FileInputStream(caminhoCertificado);
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
            System.err.println("    Certificado lido de disco com sucesso");
            return cert;
        } catch (CertificateException e) {
            System.err.println(Constantes.formatoCertificado + " não é reconhecido como formato válido");
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            System.err.println(caminhoCertificado + " não é reconhecido como caminho válido");
            e.printStackTrace();
        }
        return null;
    }

}
