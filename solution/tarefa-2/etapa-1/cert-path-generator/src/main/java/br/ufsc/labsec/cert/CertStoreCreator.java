package br.ufsc.labsec.cert;

import br.ufsc.labsec.ImplementMe;
import br.ufsc.labsec.Main;
import br.ufsc.labsec.utils.CertificateUtils;
import br.ufsc.labsec.utils.ConnectionUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.InputStream;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;


public class CertStoreCreator {
    /**
     * O tipo de repositório de certificados
     */
    private static final String CERT_STORE_INSTANCE = "Collection";

    /**
     * Retorna um CertStore do tipo Collection
     *
     * @see CertStore
     * @see CertStoreParameters
     * @see CertChainFromAiA#downloadCertificateChain(X509Certificate)
     * @return O CertStore
     */
    @ImplementMe
    public static CertStore createCertStore(X509Certificate certificate, Set<TrustAnchor> trustAnchors)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {

        Security.addProvider(new BouncyCastleProvider());


        // Create a list to hold certificates

        // Pegar os certificados das Trust Anchors (não sei por que transformar em trust anchors se precisa transformar em certificado de volta
        List<X509Certificate> certList = null;
        try {
            certList = CertChainFromAiA.downloadCertificateChain(certificate);
        }catch (Exception e){
            System.out.println("ERRO: " + e);
            
        }


        // Criar os parâmetros da certstore
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(certList);

        // Tentar criar a certstore
        try {
            return CertStore.getInstance("Collection", params, "BC");
        }catch (Exception e){
            System.out.println("ERRO: Não foi possível criar CertStore");
        }
        return null;
    }
}
