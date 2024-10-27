package br.ufsc.labsec;

import br.ufsc.labsec.cert.CertChainFromAiA;
import br.ufsc.labsec.cert.CertPathCreator;
import br.ufsc.labsec.cert.CertStoreCreator;
import br.ufsc.labsec.utils.CertificateUtils;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * Classe principal do desafio final, leia todo o enunciado antes de começar.
 *
 * <p>
 *     O objetivo deste desafio é gerar um caminho de certificação dado um certificado e sua âncora de confiança.
 * </p>
 * <p>
 *     Estão disponíveis dois certificados:
 * </p>
 *     <li> cert_CHOP_SUEY.pem
 *     <li> cert_MANEATER.pem
 * <p>
 *    É responsabilidade do candidato descobrir qual é a âncora de confiança e gerar o caminho de certificação.
 * </p>
 *
 * <p>
 *     Na saída é necessário que o candidato imprima o caminho de certificação gerado e qual foi a âncora de confiança utilizada.
 *     Exemplo de saída:
 *      <pre>
 *          {@code
 *          System.out.println("Caminho de certificação: " + certPath);
 *          System.out.println("Âncora de confiança: " + trustAnchor);}
 *      </pre>
 * </p>
 *
 * <p>
 *     Adicionalmente é encorajado que o candidato comente o código para explicar o raciocínio por trás da solução.
 * </p>
 *
 * <p>
 * Métodos a serem implementados:
 *
 * <li> {@link br.ufsc.labsec.cert.CertPathCreator#createCertPath}
 * <li> {@link br.ufsc.labsec.cert.CertPathCreator#getCertPathParameters}
 * <li> {@link br.ufsc.labsec.cert.CertStoreCreator#createCertStore}
 * <li> {@link br.ufsc.labsec.cert.CertChainFromAiA#downloadCertificateChain}
 * <li> {@link br.ufsc.labsec.cert.CertChainFromAiA#getAuthorityInformationAccess}
 *
 * <p>
 * Foram disponibilizadas classes de utilidade para auxiliar na implementação:
 * <li> {@link br.ufsc.labsec.utils}
 */
public class Main {
    static {Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());}
    static final String CHOP_SUEY = "cert_CHOP_SUEY.pem";
    static final String MANEATER = "cert_MANEATER.pem";

    static X509Certificate certificado = loadCertificate(CHOP_SUEY);



    public static Logger logger = Logger.getLogger("challenge-labsec");

    public static void main(String[] args)
            throws Exception {
        // Adicione o código aqui
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        //System.out.println(certificado);
        TrustAnchor trustAnchor = CertificateUtils.trustAnchorFromCertificate(certificado);
        System.out.println(trustAnchor);
        Set<TrustAnchor> trustAnchorSet = new LinkedHashSet<TrustAnchor>();


        List<X509Certificate> certificateList = CertChainFromAiA.downloadCertificateChain(certificado);
        for (X509Certificate cert : certificateList){
            trustAnchorSet.add(CertificateUtils.trustAnchorFromCertificate(cert));
        }

        CertPath certPath = CertPathCreator.createCertPath(certificado, trustAnchorSet);


        /*
        for (X509Certificate certificate: certPath){
            System.out.println("Subject: " + certificate.getSubjectX500Principal());
            System.out.println("Issuer: " + certificate.getIssuerX500Principal());
            //System.out.println(certificate);
            System.out.println("---------------------------------------------------------------------------");
        };
        */

        System.out.println("Caminho de certificação: " + certPath);
        System.out.println("Âncora de confiança: " + trustAnchor);




        System.exit(0);
    }



    public static X509Certificate loadCertificate(String certificado){
        // Versão modificada de:
        // https://docs.hidglobal.com/dev/auth-service/buildingapps/java/read-different-certificate-key-file-formats-with-java.htm
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            InputStream arquivo = Main.class.getClassLoader().getResourceAsStream(certificado);
            if (arquivo == null) {
                throw new FileNotFoundException("Resource not found: " + certificado);
            }
            return (X509Certificate) certFactory.generateCertificate(arquivo);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
