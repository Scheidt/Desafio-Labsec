package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import br.ufsc.labsec.pbad.hiring.Constantes;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;


/**
 * Classe responsável por gerar uma assinatura digital.
 * <p>
 * Aqui será necessário usar a biblioteca Bouncy Castle, pois ela já possui a
 * estrutura básica da assinatura implementada.
 */
public class GeradorDeAssinatura {

    private X509Certificate certificado;
    private PrivateKey chavePrivada;
    private CMSSignedDataGenerator geradorAssinaturaCms;

    /**
     * Construtor.
     */
    public GeradorDeAssinatura() {
        this.geradorAssinaturaCms = new CMSSignedDataGenerator();
    }

    /**
     * Informa qual será o assinante.
     *
     * @param certificado  certificado, no padrão X.509, do assinante.
     * @param chavePrivada chave privada do assinante.
     */
    public void informaAssinante(X509Certificate certificado,
                                 PrivateKey chavePrivada) {
        this.certificado = certificado;
        this.chavePrivada = chavePrivada;
    }

    /**
     * Gera uma assinatura no padrão CMS.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento assinado.
     */
    public CMSSignedData assinar(String caminhoDocumento) {
        try {
            CMSTypedData dadosParaAssinar = this.preparaDadosParaAssinar(caminhoDocumento);

            // Prepara informações do assinante (certificado, chave, algoritmo de hash + assinatura)
            SignerInfoGenerator informacoesAssinante = this.preparaInformacoesAssinante(this.chavePrivada, this.certificado);

            // Adiciona o gerador de informações do assinante ao gerador de assinatura principal
            this.geradorAssinaturaCms.addSignerInfoGenerator(informacoesAssinante);

            // Adiciona o certificado do signatário
            List<Certificate> listaCertificados = new ArrayList<>();
            listaCertificados.add(this.certificado);
            Store<X509CertificateHolder> armazemCertificados = new JcaCertStore(listaCertificados);
            try {
                this.geradorAssinaturaCms.addCertificates(armazemCertificados);
            } catch (CMSException e) {
                System.err.println(("Erro ao adicionar certificado em GeradorDeAssinatura: " + e.getMessage()));
                e.printStackTrace();
                return null;
            }
            
            // Gera a assinatura em si (com ou sem encapsulamento do documento)
            CMSSignedData assinatura;
            try {
                assinatura = this.geradorAssinaturaCms.generate(dadosParaAssinar, true);
                return assinatura;
            } catch (CMSException e) {
                System.err.println(("Erro ao gerar assinatura em GeradorDeAssinatura: " + e.getMessage()));
                e.printStackTrace();
                return null;
            }


        } catch (CertificateEncodingException e) {
            System.err.println(("Erro ao gerar a assinatura CMS." + e.getMessage()));
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Transforma o documento que será assinado para um formato compatível
     * com a assinatura.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento no formato correto.
     */
    private CMSTypedData preparaDadosParaAssinar(String caminhoDocumento) {
        File arquivo = new File(caminhoDocumento);
        return new CMSProcessableFile(arquivo);
    }

    /**
     * Gera as informações do assinante na estrutura necessária para ser
     * adicionada na assinatura.
     *
     * @param chavePrivada chave privada do assinante.
     * @param certificado  certificado do assinante.
     * @return Estrutura com informações do assinante.
     */
    private SignerInfoGenerator preparaInformacoesAssinante(PrivateKey chavePrivada,
                                                            Certificate certificado) {
        try {
            // Nesta linha é definido o algorítmo  de hashing + assinatura, coletados do arquivo de constantes. 
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(Constantes.algoritmoAssinatura);

            // Junta o objeto anterior com a chave privada, formando a primeira metade do output final. 
            ContentSigner contentSigner = contentSignerBuilder.build(chavePrivada);



            // Instancia e configura a estrura que calcula o hash. 
            JcaDigestCalculatorProviderBuilder providerBuilder = new JcaDigestCalculatorProviderBuilder();
            DigestCalculatorProvider digestCalculatorProvider = providerBuilder.build();

            // Inicia o construtor principal com a função que calcula o hash. 
            JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider);

            // Junta o construtor com o contentSigner (que representa qual algorítmo de hash + assinatura é utilizado, junto da chave privada) 
            // e o certificado, e retorna a build pronta. 
            SignerInfoGenerator siginfo = infoGeneratorBuilder.build(contentSigner, (X509Certificate) certificado);
            System.out.println("    Sucesso em gerar informações do signatário");
            return siginfo;
        } catch (CertificateEncodingException | OperatorCreationException e) {
            System.err.println("Erro ao buildar o SignerInfoGenerator em GeradorDeAssinatura.java: " + e.getMessage());
            e.printStackTrace();
        }
        return null;

    }

    /**
     * Escreve a assinatura no local apontado.
     *
     * @param arquivo    arquivo que será escrita a assinatura.
     * @param assinatura objeto da assinatura.
     */
    public void escreveAssinatura(OutputStream arquivo, CMSSignedData assinatura) {
        try {
            byte[] bytesAssinatura = assinatura.getEncoded();
            arquivo.write(bytesAssinatura);
            System.out.println("    Sucesso em salvamento em disco!");
        } catch (IOException e) {
            throw new RuntimeException("Erro ao escrever a assinatura no arquivo.", e);
        }
    }

}
