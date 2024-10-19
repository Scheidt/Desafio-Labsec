package br.ufsc.labsec.cert;

import br.ufsc.labsec.ImplementMe;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Set;


public class CertPathCreator {
    public static String BUILDER_INSTANCE = "PKIX";

    /**
     * Cria um caminho de certificação para o certificado dado
     * @see CertPathCreator#getCertPathParameters(X509Certificate, Set)
     * @see CertPathBuilder
     * @param certificate O certificado final do caminho de certificação
     * @param trustAnchors As possíveis âncoras de confiança para o caminho de certificação
     * @return O caminho de certificação
     */
    @ImplementMe
    public static CertPath createCertPath(X509Certificate certificate, Set<TrustAnchor> trustAnchors)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Implemente: CertPathCreator.createCertPath");
    }


    /**
     * Cria os parâmetros para a construção do caminho de certificação
     * @see CertPathCreator#createCertPath(X509Certificate, Set)
     * @param certificate O certificado final do caminho de certificação
     * @param trustAnchors As possíveis âncoras de confiança para o caminho de certificação
     * @return Os parâmetros para a construção do caminho de certificação
     */
    @ImplementMe
    public static CertPathParameters getCertPathParameters(X509Certificate certificate,
                                                            Set<TrustAnchor> trustAnchors)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Implemente: CertPathCreator.getCertPathParameters");
    }
}
