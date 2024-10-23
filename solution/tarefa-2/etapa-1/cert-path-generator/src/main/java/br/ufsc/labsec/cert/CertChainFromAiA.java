package br.ufsc.labsec.cert;

import br.ufsc.labsec.utils.CertificateUtils;
import br.ufsc.labsec.utils.ConnectionUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;


public class CertChainFromAiA {


    // Honestamente não lembro onde achei esssa função. Mas ela foi praticamente inteira mudada então não seria reconhecível
    /**
     * Baixa a cadeia de certificação de um certificado a partir do Authority Information Access
     * @param certificate O certificado
     * @return A lista de certificados do Authority Information Access
     * @see #getAuthorityInformationAccess(X509Certificate)
     */
    public static List<X509Certificate> downloadCertificateChain(X509Certificate certificate) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();
        List<X509Certificate> visitedCertificates = new ArrayList<>();
        X509Certificate currentCertificate = certificate;
        CertificateFactory certFact = CertificateFactory.getInstance("X.509");
        chain.add(currentCertificate);

        // Verifica se o certificado é autoassinado
        while (!CertificateUtils.isSelfSigned(currentCertificate)) {
            visitedCertificates.add(currentCertificate);

            AuthorityInformationAccess aia = getAuthorityInformationAccess(currentCertificate);
            if (aia == null) {
                System.out.println("ERRO: Authority Information Access não encontrado no certificado: " +
                        currentCertificate.getSubjectDN());
                break; // Interrompe o loop se o AIA não estiver presente
            }

            URI uriDoCertificado = getAccessLocation(currentCertificate);
            if (uriDoCertificado == null) {
                throw new Exception("ERRO: URI do AIA não encontrada no certificado: " + currentCertificate.getSubjectDN());
            }

            // Tenta baixar o próximo certificado na cadeia
            InputStream inStream = null;
            try {
                inStream = ConnectionUtils.get(uriDoCertificado);
                System.out.println(uriDoCertificado);
                X509Certificate downloadedCert = (X509Certificate) certFact.generateCertificate(inStream);
                if (downloadedCert == null) {
                    throw new Exception("ERRO: Não foi possível baixar o certificado a partir do URI: " + uriDoCertificado);
                }

                // Atualiza o certificado atual
                currentCertificate = downloadedCert;
                chain.add(currentCertificate);
            } catch (Exception e) {
                System.err.println("ERRO ao baixar ou processar o certificado de " + uriDoCertificado + ": " + e.getMessage());
                break; // Interrompe o loop se ocorrer um erro no download
            } finally {
                if (inStream != null) {
                    inStream.close();
                }
            }
        }

        return chain;
    }
            /*

            for (URI uri : issuerUris) {
                try (InputStream inStream = ConnectionUtils.get(uri)) { // Função get(URI) fornecida


                    if (CertificateUtils.isIssuer(downloadedCert, currentCert)) { // Função isIssuer fornecida
                        issuerCert = downloadedCert;
                        break; // Encontramos o emissor correto
                    }
                } catch (Exception e) {
                    // Log ou trate o erro conforme necessário
                    System.err.println("Erro ao baixar ou processar o certificado de " + uri + ": " + e.getMessage());
                    // Continua para o próximo URI se ocorrer um erro
                }
            }

            if (issuerCert == null) {
                throw new Exception("Não foi possível encontrar o certificado emissor para " + currentCert.getSubjectDN());
            }

            if (visitedCertificates.contains(issuerCert)) {
                throw new Exception("Loop detectado na cadeia de certificados com o certificado: " + issuerCert.getSubjectDN());
            }

            currentCert = issuerCert; // Avança para o próximo certificado na cadeia
        }

        return chain;
    }


    private static List<URI> getIssuerCertificateURIs(AuthorityInformationAccess aia) {
        List<URI> uris = new ArrayList<>();
        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();

        for (AccessDescription ad : accessDescriptions) {
            if (ad.getAccessMethod().equals(AccessDescription.id_ad_caIssuers)) {
                GeneralName location = ad.getAccessLocation();
                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String uriStr = DERIA5String.getInstance(location.getName()).getString();
                    try {
                        URI uri = new URI(uriStr);
                        uris.add(uri);
                    } catch (URISyntaxException e) {
                        // Log ou trate o URI inválido conforme necessário
                        System.err.println("URI inválido encontrado no AIA: " + uriStr);
                        continue; // Ignora URIs inválidos
                    }
                }
            }
        }
        return uris;
    }
    */

    // Feito com base em:
    // https://stackoverflow.com/questions/44846091/how-to-parse-authoritiyinformation-from-x509certificate-object
    // Modificado para usar a função getAuthorityInformationAcess que vocês sugeriram criar
    // Depois de alguns testes percebi que ela não funciona e que tenho que fazer muitas modificações
    // Esquece, funciona e o problema vem de outro lugar
    public static URI getAccessLocation(X509Certificate certificate) throws IOException, URISyntaxException {
        final ASN1ObjectIdentifier ocspAccessMethod = X509ObjectIdentifiers.ocspAccessMethod;

        AuthorityInformationAccess authorityInformationAccess = CertChainFromAiA.getAuthorityInformationAccess(certificate);
        if (authorityInformationAccess == null) {
            return null;
        }

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription.getAccessMethod().equals(ocspAccessMethod)) {
                GeneralName gn = accessDescription.getAccessLocation();
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    DERIA5String uriString = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
                    return new URI(uriString.getString());
                }
            }
        }

        return null;
    }

    /**
     * Retorna o Authority Information Access (AiA) de um certificado
     * @param certificate O certificado
     * @return O Authority Information Access (AiA)
     **/
    public static AuthorityInformationAccess getAuthorityInformationAccess(X509Certificate certificate) {
        // Modificado de: https://stackoverflow.com/questions/44846091/how-to-parse-authoritiyinformation-from-x509certificate-object
        // (A pessoa no stackoverflow não incluiu um return e isso me causou muita dor debugando)
        try {
            byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
            ASN1InputStream ais1 = new ASN1InputStream(new ByteArrayInputStream(authInfoAccessExtensionValue ));
            DEROctetString oct = (DEROctetString) (ais1.readObject());
            ASN1InputStream ais2 = new ASN1InputStream(oct.getOctets());
            return AuthorityInformationAccess.getInstance(ais2.readObject());
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
