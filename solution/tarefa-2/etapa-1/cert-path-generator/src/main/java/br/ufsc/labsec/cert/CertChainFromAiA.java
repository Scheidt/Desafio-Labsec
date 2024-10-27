package br.ufsc.labsec.cert;

import br.ufsc.labsec.utils.CertificateUtils;
import br.ufsc.labsec.utils.ConnectionUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;


public class CertChainFromAiA {


    /**
     * Baixa a cadeia de certificação de um certificado a partir do Authority Information Access
     *
     * @param certificate O certificado
     * @return A lista de certificados do Authority Information Access
     * @see #getAuthorityInformationAccess(X509Certificate)
     */
    public static List<X509Certificate> downloadCertificateChain(X509Certificate certificate) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();
        CertificateFactory certFact = CertificateFactory.getInstance("X.509");
        chain.add(certificate);
        if (CertificateUtils.isSelfSigned(certificate)) {
            return chain;
        }


        AuthorityInformationAccess aia = getAuthorityInformationAccess(certificate);
        assert aia != null;
        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();


        URI uri = null;
        for (AccessDescription accessDescription : aia.getAccessDescriptions()) {
            // Check if it's a caIssuers type
            if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                // Print the URL
                uri = new URI(accessDescription.getAccessLocation().getName().toString());
            }
        }
        if (uri == null) {
            System.out.println("Erro pegando URI do AiA do certificado: " + certificate.getSubjectDN());

        }
        //System.out.println(uri);
        InputStream inStream = ConnectionUtils.get(uri);
        // Pega o arquivo .p7c do certificado:
        CMSSignedData p7c = new CMSSignedData(inStream);
        //System.out.println(p7c);

        Store<X509CertificateHolder> certStore = p7c.getCertificates();
        Collection<X509CertificateHolder> certHolders = certStore.getMatches(null);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

        for (X509CertificateHolder certHolder : certHolders) {
            X509Certificate newCertificate = converter.getCertificate(certHolder);
            chain.add(newCertificate);
        }
        return chain;
    }

    /**
     * Retorna o Authority Information Access (AiA) de um certificado
     *
     * @param certificate O certificado
     * @return O Authority Information Access (AiA)
     **/
    public static AuthorityInformationAccess getAuthorityInformationAccess(X509Certificate certificate) {
        // Modificado de: https://stackoverflow.com/questions/44846091/how-to-parse-authoritiyinformation-from-x509certificate-object
        try {
            byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());

            // Verifica se o valor da extensão é nulo
            if (authInfoAccessExtensionValue == null) {
                System.err.println("AVISO: O Authority Information Access não está presente no certificado " + certificate.getSubjectDN());
                return null;
            }

            ASN1InputStream ais1 = new ASN1InputStream(new ByteArrayInputStream(authInfoAccessExtensionValue));
            DEROctetString oct = (DEROctetString) (ais1.readObject());
            ASN1InputStream ais2 = new ASN1InputStream(oct.getOctets());
            //System.out.println("AiA: " + AuthorityInformationAccess.getInstance(ais2.readObject()) + " Fim AiA");

            return AuthorityInformationAccess.getInstance(ais2.readObject());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
