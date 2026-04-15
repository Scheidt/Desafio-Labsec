package br.ufsc.labsec.pbad.selectionchallengepsc.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

/**
 * Utilitário para geração de chaves e emissão de certificados X.509 via BouncyCastle.
 */
public class CertificateGenerator {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Gera par de chaves RSA 2048 bits. */
    public static KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(2048, new SecureRandom());
        return gen.generateKeyPair();
    }

    /** Gera par de chaves ML-DSA 87 (CRYSTALS-Dilithium nível 5). */
    public static KeyPair generateMlDsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ML-DSA", "BC");
        gen.initialize(MLDSAParameterSpec.ml_dsa_87, new SecureRandom());
        return gen.generateKeyPair();
    }

    /**
     * Emite um certificado X.509 assinado pela CA fornecida.
     *
     * @param subjectDN    DN do sujeito, ex: "CN=Nome, OU=PBAD, O=UFSC, C=BR"
     * @param subjectKey   Chave pública do sujeito
     * @param caPrivateKey Chave privada da CA
     * @param caCert       Certificado da CA
     * @return Certificado X.509 emitido
     * @throws Exception se ocorrer um erro durante a emissão do certificado
     */
    public static X509Certificate issueCertificate(String subjectDN,
                                                    PublicKey subjectKey,
                                                    PrivateKey caPrivateKey,
                                                    X509Certificate caCert) throws Exception {
        // Usa o DER do subject da CA para preservar a codificação exata
        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        X500Name subject = new X500Name(subjectDN);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, subjectKey);

        // CA é RSA, então assina com SHA256withRSA independentemente do algoritmo do sujeito
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(caPrivateKey);

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    /**
     * Carrega um KeyStore PKCS#12 a partir de bytes.
     *
     * @param p12Bytes Bytes do arquivo .p12
     * @param password Senha do arquivo
     * @return KeyStore carregado
     * @throws Exception se ocorrer um erro durante o carregamento do KeyStore
     */
    public static KeyStore loadP12(byte[] p12Bytes, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new ByteArrayInputStream(p12Bytes), password.toCharArray());
        return ks;
    }

    /**
     * Extrai a chave privada do primeiro alias de um KeyStore.
     * @param ks KeyStore do qual extrair a chave privada
     * @param password Senha do KeyStore para acessar a chave privada
     * @return Chave privada extraída
     * @throws Exception se ocorrer um erro durante a extração da chave privada
     */
    public static PrivateKey getPrivateKey(KeyStore ks, String password) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                return (PrivateKey) ks.getKey(alias, password.toCharArray());
            }
        }
        throw new KeyStoreException("Nenhuma chave privada encontrada no KeyStore");
    }

    /**
     * Extrai o certificado do primeiro alias de um KeyStore.
     * @param ks KeyStore do qual extrair o certificado
     * @return Certificado extraído
     * @throws Exception se ocorrer um erro durante a extração do certificado
     */
    public static X509Certificate getCertificate(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isCertificateEntry(alias) || ks.isKeyEntry(alias)) {
                return (X509Certificate) ks.getCertificate(alias);
            }
        }
        throw new KeyStoreException("Nenhum certificado encontrado no KeyStore");
    }

    /**
     * Carrega um certificado X.509 a partir de bytes DER.
     * @param derBytes Bytes DER do certificado
     * @return Certificado X.509 carregado
     * @throws Exception se ocorrer um erro durante o carregamento do certificado
     */
    public static X509Certificate loadCertificate(byte[] derBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
    }
}
