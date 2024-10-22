package br.ufsc.labsec;

import java.io.InputStream;
import java.net.URI;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

public class Main {
    static final String CHOP_SUEY = "cert_CHOP_SUEY.pem";
    static final String MANEATER = "cert_MANEATER.pem";

    public static Logger logger = Logger.getLogger("challenge-labsec");

    public static void main(String[] args)
        throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


    }
    public List<X509Certificate> getCertificateChain(X509Certificate cert) throws Exception {

        List<X509Certificate> chain = new ArrayList<>();
        Set<Principal> seenPrincipals = new HashSet<>();
        chain.add(cert);
        seenPrincipals.add(cert.getSubjectX500Principal());

        while (!isSelfSigned(cert)) {
            X509Certificate issuerCert = null;

            // Obter URIs dos certificados emissores
            List<String> issuerURIs = getAuthorityInfoAccessURIs(cert, AccessDescription.id_ad_caIssuers.getId());

            for (String uri : issuerURIs) {
                try {
                    InputStream inStream = get(new URI(uri)); // Função 'get' pré-implementada
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate possibleIssuerCert = (X509Certificate) cf.generateCertificate(inStream);
                    inStream.close();

                    // Verificar se este é o certificado emissor
                    cert.verify(possibleIssuerCert.getPublicKey());
                    issuerCert = possibleIssuerCert;
                    break;
                } catch (Exception e) {
                    // Tentar a próxima URI
                }
            }

            if (issuerCert == null) {
                // Não foi possível encontrar o certificado emissor
                break;
            }

            if (seenPrincipals.contains(issuerCert.getSubjectX500Principal())) {
                // Evitar loops
                break;
            }

            chain.add(issuerCert);
            seenPrincipals.add(issuerCert.getSubjectX500Principal());
            cert = issuerCert;
        }

        return chain;
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            // Verificar a assinatura com a própria chave pública
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private List<String> getAuthorityInfoAccessURIs(X509Certificate cert, String accessMethodOID) throws Exception {
        byte[] extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extensionValue == null) {
            return Collections.emptyList();
        }

        ASN1Primitive aiaExtension = JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaExtension);

        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
        List<String> uris = new ArrayList<>();

        for (AccessDescription ad : accessDescriptions) {
            if (ad.getAccessMethod().equals(new ASN1ObjectIdentifier(accessMethodOID))) {
                GeneralName gn = ad.getAccessLocation();
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String uri = DERIA5String.getInstance(gn.getName()).getString();
                    uris.add(uri);
                }
            }
        }
        return uris;
    }

    // Supondo que a função 'get' está implementada em outro lugar
    private InputStream get(URI uri) {
        // Implementação da função 'get' não mostrada
        return null;
    }
}
