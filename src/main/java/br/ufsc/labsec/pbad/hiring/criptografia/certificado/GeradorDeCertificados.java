package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import br.ufsc.labsec.pbad.hiring.Constantes;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;


import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Classe responsável por gerar certificados no padrão X.509.
 * <p>
 * Um certificado é basicamente composto por três partes, que são:
 * <ul>
 * <li>
 * Estrutura de informações do certificado;
 * </li>
 * <li>
 * Algoritmo de assinatura;
 * </li>
 * <li>
 * Valor da assinatura.
 * </li>
 * </ul>
 */

public class GeradorDeCertificados {
    /**
     * Esta classe foi completamente modificada, observe no relatório minha razão para isso.
     * Em suma, a forma anterior utilizava classes depreciadas, então mudei a classe usada e isso gerou uma modificação completa da forma do código.
     */

    /**
     * Gera a estrutura de informações de um certificado.
     *
     * @param chavePublica  chave pública do titular.
     * @param numeroDeSerie número de série do certificado.
     * @param nome          nome do titular.
     * @param nomeAc        nome da autoridade emissora.
     * @param dias          a partir da data atual, quantos dias de validade
     *                      terá o certificado.
     * @return Estrutura de informações do certificado.
     */
    public X509Certificate gerarCertificado(PublicKey chavePublicaTitular, PrivateKey chavePrivadaAc,
                                            long numeroDeSerie, String nomeTitular,
                                            String nomeAc, int diasDeValidade) {
        try {
            //Nomes
            X500Name issuer = new X500Name(nomeAc);
            X500Name subject = new X500Name(nomeTitular);

            //Validade
            Calendar calendar = Calendar.getInstance();
            Date dataInicio = calendar.getTime();
            calendar.add(Calendar.DAY_OF_YEAR, diasDeValidade);
            Date dataFim = calendar.getTime();

            //Criação do builder
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(numeroDeSerie),
                dataInicio,
                dataFim,
                subject,
                chavePublicaTitular
            );

            //Definir algoritmo de assinatura
            ContentSigner signer = new JcaContentSignerBuilder(Constantes.algoritmoAssinatura)
                                       .build(chavePrivadaAc);

            //Build e assinatura
            X509CertificateHolder holder = builder.build(signer);

            //retorna o certificado no formato X509Certificate
            X509Certificate certificado = new JcaX509CertificateConverter().getCertificate(holder);
            System.out.println("    Certificado gerado com sucesso!");
            return certificado;

        } catch (OperatorCreationException e) {
            System.err.println("Erro durante build de algoritmo de assinatura. Algoritmo utilizado: " + Constantes.algoritmoAssinatura + e.getMessage());
            e.printStackTrace();
        } catch (CertificateException e) {
            System.err.println("Erro durante conversão de certificado: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }


    /**
     * Gera a estrutura de informações de um certificado. Possui um argumento optativo
     * para escolha de um outro algoritmo de assinatura.
     *
     * @param chavePublica  chave pública do titular.
     * @param numeroDeSerie número de série do certificado.
     * @param nome          nome do titular.
     * @param nomeAc        nome da autoridade emissora.
     * @param dias          a partir da data atual, quantos dias de validade
     *                      terá o certificado.
     * @param algoritmo     algoritmo de assinatura utilizado
     * @return Estrutura de informações do certificado.
     */
    public X509Certificate gerarCertificado(PublicKey chavePublicaTitular, PrivateKey chavePrivadaAc,
                                            long numeroDeSerie, String nomeTitular,
                                            String nomeAc, int diasDeValidade, String algoritmo) {
        try {
            //Nomes
            X500Name issuer = new X500Name(nomeAc);
            X500Name subject = new X500Name(nomeTitular);

            //Validade
            Calendar calendar = Calendar.getInstance();
            Date dataInicio = calendar.getTime();
            calendar.add(Calendar.DAY_OF_YEAR, diasDeValidade);
            Date dataFim = calendar.getTime();

            //Criação do builder
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(numeroDeSerie),
                dataInicio,
                dataFim,
                subject,
                chavePublicaTitular
            );

            //Definir algoritmo de assinatura
            ContentSigner signer = new JcaContentSignerBuilder(algoritmo)
                                       .build(chavePrivadaAc);

            //Build e assinatura
            X509CertificateHolder holder = builder.build(signer);

            //retorna o certificado no formato X509Certificate
            X509Certificate certificado = new JcaX509CertificateConverter().getCertificate(holder);
            System.out.println("    Certificado gerado com sucesso!");
            return certificado;

        } catch (OperatorCreationException e) {
            System.err.println("Erro durante build de algoritmo de assinatura. Algoritmo utilizado: " + Constantes.algoritmoAssinatura + e.getMessage());
            e.printStackTrace();
        } catch (CertificateException e) {
            System.err.println("Erro durante conversão de certificado: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

}
