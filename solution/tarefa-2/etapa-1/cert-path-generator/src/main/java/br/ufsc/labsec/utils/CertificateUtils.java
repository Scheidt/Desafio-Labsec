package br.ufsc.labsec.utils;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.x509.Extension;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

public class CertificateUtils {

    /**
     * Cria uma âncora de confiança a partir de um certificado X.509
     * @param certificate O certificado
     * @return A âncora de confiança
     */
    public static TrustAnchor trustAnchorFromCertificate(X509Certificate certificate) {
        final byte CONSTRUCTED_OCTET_STRING = BERTags.OCTET_STRING | BERTags.CONSTRUCTED;
        byte[] nameConstraint = certificate.getExtensionValue(Extension.nameConstraints.getId());
        if (nameConstraint != null && nameConstraint.length > 0 &&
                (nameConstraint[0] == BERTags.OCTET_STRING || nameConstraint[0] == CONSTRUCTED_OCTET_STRING)) {
            ASN1OctetString octetString = ASN1OctetString.getInstance(nameConstraint);
            nameConstraint = octetString.getOctets();
        }
        return new TrustAnchor(certificate, nameConstraint);
    }

    /**
     * Verifica se um certificado é autoassinado
     * @see CertificateUtils#isIssuer(X509Certificate, X509Certificate)
     * @param certificate O certificado
     * @return Se o certificado é autoassinado
     */
    public static boolean isSelfSigned(X509Certificate certificate) {
        return isIssuer(certificate, certificate);
    }

    /**
     * Verifica se um certificado tem uma âncora de confiança como emissor
     * @see CertificateUtils#isIssuer(X509Certificate, X509Certificate)
     * @param certificate O certificado
     * @param trustAnchors As âncoras de confiança
     * @return Se o certificado tem uma âncora de confiança como emissor
     */
    public static boolean hasTrustAnchorAsIssuer(X509Certificate certificate, Set<TrustAnchor> trustAnchors) {
        return trustAnchors.stream()
                .map(TrustAnchor::getTrustedCert)
                .anyMatch(trustAnchor -> isIssuer(trustAnchor, certificate));
    }

    /**
     * Verifica se um certificado é o emissor de outro certificado
     * @param issuer O certificado emissor
     * @param certificate O certificado
     * @return Se o certificado é emitido pelo emissor
     */
    public static boolean isIssuer(X509Certificate issuer, X509Certificate certificate) {
        try {
            // Verificação pelo nome do emissor (mais rápido)
            if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                return false;
            }
            // Verificação pela chave pública do emissor
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException |
                 SignatureException | InvalidKeyException | NoSuchProviderException ignored) {
            return false;
        }
    }
}
