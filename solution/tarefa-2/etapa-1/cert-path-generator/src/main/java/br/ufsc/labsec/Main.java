package br.ufsc.labsec;

import java.security.Security;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Logger;

import br.ufsc.labsec.utils.CertificateChainBuilder;

public class Main {
    static final String CHOP_SUEY = "cert_CHOP_SUEY.pem";
    static final String MANEATER = "cert_MANEATER.pem";

    public static Logger logger = Logger.getLogger("challenge-labsec");

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        CertificateChainBuilder builder = new CertificateChainBuilder();
        X509Certificate certificado = CertificateChainBuilder.carregarCertificado(CHOP_SUEY);
        List<X509Certificate> chain = builder.getCertificateChain(certificado);
        System.out.println(chain);
        for (X509Certificate cert : chain){
            System.out.println("-----------------------------------------------------------------------------------------------------------------------------------------------------------");
            System.out.println(cert);
        }
    }
}
