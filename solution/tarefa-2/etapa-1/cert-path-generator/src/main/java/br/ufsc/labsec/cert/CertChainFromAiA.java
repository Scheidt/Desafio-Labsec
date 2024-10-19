package br.ufsc.labsec.cert;

import br.ufsc.labsec.ImplementMe;
import br.ufsc.labsec.Main;
import br.ufsc.labsec.utils.ConnectionUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;

import java.io.InputStream;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;


public class CertChainFromAiA {

    /**
     * Baixa a cadeia de certificação de um certificado a partir do Authority Information Access
     * @param certificate O certificado
     * @return A lista de certificados do Authority Information Access
     * @see #getAuthorityInformationAccess(X509Certificate)
     */
    @ImplementMe
    public static List<X509Certificate> downloadCertificateChain(X509Certificate certificate) {
        throw new UnsupportedOperationException("Implemente: CertChainFromAiA.downloadCertificateChain");
    }

    /**
     *
     * @param certificate
     * @return
     */
    @ImplementMe
    public static AuthorityInformationAccess getAuthorityInformationAccess(X509Certificate certificate) {
        throw new UnsupportedOperationException("Implemente: CertChainFromAiA.getAuthorityInformationAccess");
    }
}
