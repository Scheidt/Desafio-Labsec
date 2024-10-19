package br.ufsc.labsec;

import br.ufsc.labsec.cert.CertPathCreator;
import br.ufsc.labsec.utils.CertificateUtils;

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
    static final String CHOP_SUEY = "cert_CHOP_SUEY.pem";
    static final String MANEATER = "cert_MANEATER.pem";

    public static Logger logger = Logger.getLogger("challenge-labsec");

    public static void main(String[] args)
            throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Adicione o código aqui
        System.exit(0);
    }

}