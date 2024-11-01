package br.ufsc.labsec.cert;

import br.ufsc.labsec.ImplementMe;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.InvalidAlgorithmParameterException;
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
            throws Exception {

        // Adaptado em parte de: https://stackoverflow.com/questions/2457795/x-509-certificate-validation-with-java-and-bouncycastle

        Security.addProvider(new BouncyCastleProvider());


        CertStore certStore = CertStoreCreator.createCertStore(certificate, trustAnchors);
        CertPathParameters certPathParameters = getCertPathParameters(certificate, trustAnchors);

        if (certPathParameters instanceof PKIXBuilderParameters) {
            ((PKIXBuilderParameters) certPathParameters).addCertStore(certStore);;
        }


        try {
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance(BUILDER_INSTANCE, "BC");
            CertPathBuilderResult result = certPathBuilder.build(certPathParameters);
            CertPath certPath = result.getCertPath();
            // Imprimir todos os certificados no CertPath resultante
            /*
            System.out.println("Certificados no CertPath:");
            for (Certificate cert : certPath.getCertificates()) {
                System.out.println(((X509Certificate) cert).getSubjectX500Principal());
            }
            */

            return certPath;

        } catch (CertPathBuilderException e) {
            System.out.println("ERRO: Não foi possível construir o CertPath: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("ERRO: " + e);
        }

        return null;
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

        // Código adaptado da resposta de:
        // https://stackoverflow.com/questions/13671487/generate-x509certificate-certpath-in-java

        Security.addProvider(new BouncyCastleProvider());


        // Define o certificado final
        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(certificate);

        // Cria os parametros
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, certSelector);

        pkixParams.setRevocationEnabled(false);


        return pkixParams;
    }
}
