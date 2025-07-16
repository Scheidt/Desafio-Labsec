package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

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
    public TBSCertificate gerarEstruturaCertificado(PublicKey chavePublica,
                                                    int numeroDeSerie, String nome,
                                                    String nomeAc, int dias) {
        // TODO implementar
        return null;
    }

    /**
     * Gera valor da assinatura do certificado.
     *
     * @param estruturaCertificado estrutura de informações do certificado.
     * @param chavePrivadaAc       chave privada da AC que emitirá esse
     *                             certificado.
     * @return Bytes da assinatura.
     */
    public DERBitString geraValorDaAssinaturaCertificado(TBSCertificate estruturaCertificado,
                                                         PrivateKey chavePrivadaAc) {
        // TODO implementar
        return null;
    }

    /**
     * Gera um certificado.
     *
     * @param estruturaCertificado  estrutura de informações do certificado.
     * @param algoritmoDeAssinatura algoritmo de assinatura.
     * @param valorDaAssinatura     valor da assinatura.
     * @return Objeto que representa o certificado.
     * @see ASN1EncodableVector
     */
    public X509Certificate gerarCertificado(TBSCertificate estruturaCertificado,
                                            AlgorithmIdentifier algoritmoDeAssinatura,
                                            DERBitString valorDaAssinatura) {
        // TODO implementar
        return null;
    }

}
