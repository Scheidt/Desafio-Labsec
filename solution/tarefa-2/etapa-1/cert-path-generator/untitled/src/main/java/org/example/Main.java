package org.example;

import org.bouncycastle.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class Main{
    public static void main (String[] args){

        // Carregar os certificados dos arquivos .pem usando Bouncy Castle.

        // Modificado de:
        // https://www.baeldung.com/java-bouncy-castle
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate chopSuey = carregarCertificado("certificados/cert_CHOP_SUEY.pem");
        X509Certificate manEater = carregarCertificado("certificados/cert_MANEATER.pem");


        //Construir a cadeia de certificados (certification path) entre os dois certificados.
        //CertPathBuilder()

    }

    public static X509Certificate carregarCertificado (String path){
        // Versão modificada de:
        // https://docs.hidglobal.com/dev/auth-service/buildingapps/java/read-different-certificate-key-file-formats-with-java.htm
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            FileInputStream file = new FileInputStream(path);
            return (X509Certificate) certFactory.generateCertificate(file);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
