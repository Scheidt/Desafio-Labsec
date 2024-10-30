package br.ufsc.labsec.cert;

import br.ufsc.labsec.utils.CertificateUtils;
import br.ufsc.labsec.utils.ConnectionUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
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
        // Não listei de onde peguei esse código, pois ele é uma mistura de vários códigos com um pouco de trial-and-error
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(certificate);
        if (CertificateUtils.isSelfSigned(certificate)){
            return chain;
        }

        AuthorityInformationAccess aia = getAuthorityInformationAccess(certificate);
        assert aia != null;
        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();


        URI uri = null;
        for (AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                uri = new URI(accessDescription.getAccessLocation().getName().toString());
            }
        }
        if (uri == null) {
            System.out.println("ERRO: Não foi possível pegar URI do AiA do certificado: " + certificate.getSubjectDN());

        }
        // Pega o arquivo .p7c do certificado com a função get e o carrrega:
        InputStream inStream = ConnectionUtils.get(uri);
        CMSSignedData p7c = new CMSSignedData(inStream);

        // Adaptado de: https://stackoverflow.com/questions/6370368/bouncycastle-x509certificateholder-to-x509certificate
        // Converte a store em uma lista de certificados
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
                System.err.println("ERRO: O Authority Information Access não está presente no certificado " + certificate.getSubjectDN());
                return null;
            }

            ASN1InputStream ais1 = new ASN1InputStream(new ByteArrayInputStream(authInfoAccessExtensionValue));
            DEROctetString oct = (DEROctetString) (ais1.readObject());
            ASN1InputStream ais2 = new ASN1InputStream(oct.getOctets());

            return AuthorityInformationAccess.getInstance(ais2.readObject());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
