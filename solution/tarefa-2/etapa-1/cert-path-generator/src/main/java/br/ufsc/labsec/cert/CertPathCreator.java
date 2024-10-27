package br.ufsc.labsec.cert;

import br.ufsc.labsec.ImplementMe;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
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

        // Ensure Bouncy Castle is registered as a security provider

        Security.addProvider(new BouncyCastleProvider());


        // Create a CertStore containing the certificate and trust anchors
        CertStore certStore = CertStoreCreator.createCertStore(certificate, trustAnchors);

        // Get CertPathParameters using the previous function
        CertPathParameters certPathParameters = getCertPathParameters(certificate, trustAnchors);

        // Add the CertStore to the PKIX parameters
        if (certPathParameters instanceof PKIXBuilderParameters) {
            ((PKIXBuilderParameters) certPathParameters).addCertStore(certStore);
        }
        CertPath certPath = null;
        try {
            // Create a CertPathBuilder using Bouncy Castle provider
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
            CertPathBuilderResult result = certPathBuilder.build(certPathParameters);
            certPath = result.getCertPath();
        } catch (Exception e){
            System.out.println("ERRO: Não foi possível criar o CertPath: " + e);
        }


        return certPath;
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
            throws InvalidAlgorithmParameterException{

        // Ensure Bouncy Castle is registered as a security provider
        Security.addProvider(new BouncyCastleProvider());


        // Create PKIX parameters with the given trust anchors
        PKIXParameters pkixParams = new PKIXParameters(trustAnchors);

        // Set the certificate constraints to the provided certificate
        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(certificate);
        pkixParams.setTargetCertConstraints(certSelector);

        // Optionally, disable CRL checking (revocation checking)
        pkixParams.setRevocationEnabled(false);

        return pkixParams;
    }
}
