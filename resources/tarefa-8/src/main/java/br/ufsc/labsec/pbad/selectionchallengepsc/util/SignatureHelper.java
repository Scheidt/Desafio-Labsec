package br.ufsc.labsec.pbad.selectionchallengepsc.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Utilitário para operações de assinatura digital usando BouncyCastle.
 */
public class SignatureHelper {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Reconstrói uma chave privada a partir de bytes PKCS#8 DER.
     * O algoritmo é determinado pelo tipo de chave pública do certificado correspondente.
     *
     * @param privateKeyBytes Bytes PKCS#8 DER da chave privada
     * @param certificateBytes Bytes DER do certificado X.509 correspondente
     * @return Chave privada reconstruída
     * @throws Exception se ocorrer um erro durante a reconstrução da chave
     */
    public static PrivateKey loadPrivateKey(byte[] privateKeyBytes, byte[] certificateBytes) throws Exception {
        X509Certificate cert = (X509Certificate) CertificateFactory
                .getInstance("X.509", "BC")
                .generateCertificate(new java.io.ByteArrayInputStream(certificateBytes));

        String algorithm = cert.getPublicKey().getAlgorithm();
        String factoryAlgorithm = algorithm.contains("DILITHIUM") || algorithm.contains("ML-DSA")
                ? "ML-DSA" : algorithm;

        KeyFactory keyFactory = KeyFactory.getInstance(factoryAlgorithm, "BC");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    /**
     * Assina os bytes de hash usando a chave privada fornecida.
     * <ul>
     *   <li>RSA: usa {@code NONEwithRSA} — aplica padding PKCS#1 v1.5 sem re-hash</li>
     *   <li>ML-DSA: usa {@code ML-DSA} — trata o hash como mensagem a assinar</li>
     * </ul>
     *
     * @param privateKey  Chave privada a usar
     * @param hashBytes   Bytes do hash a ser assinado
     * @return Bytes da assinatura digital
     * @throws Exception se ocorrer um erro durante a assinatura
     */
    public static byte[] signHash(PrivateKey privateKey, byte[] hashBytes) throws Exception {
        String algorithm = determineSignatureAlgorithm(privateKey);
        Signature signer = Signature.getInstance(algorithm, "BC");
        signer.initSign(privateKey);
        signer.update(hashBytes);
        return signer.sign();
    }

    private static String determineSignatureAlgorithm(PrivateKey key) {
        String alg = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(alg)) {
            return "NONEwithRSA";
        }
        // ML-DSA (CRYSTALS-Dilithium) e variantes
        return "ML-DSA";
    }
}
