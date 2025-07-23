package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignatureVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * Classe responsável por verificar a integridade de uma assinatura.
 */
public class VerificadorDeAssinatura {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Verifica a integridade de uma assinatura digital no padrão CMS.
     *
     * @param certificado certificado do assinante.
     * @param assinatura  documento assinado.
     * @return {@code true} se a assinatura for íntegra, e {@code false} do
     * contrário.
     */
    public boolean verificarAssinatura(X509Certificate certificado,
                                       CMSSignedData assinatura){
        try {
            SignerInformationVerifier verificador = geraVerificadorInformacoesAssinatura(certificado);
            SignerInformation sigInfo = pegaInformacoesAssinatura(assinatura);
            boolean resultado = sigInfo.verify(verificador);
            System.out.println("    Sucesso na verificação");
            return resultado;
        } catch (CMSException e) {
                System.err.println("Erro ao verificar assinatura: " + e.getMessage());
                e.printStackTrace();
        }
        return false;
    }

    /**
     * Gera o verificador de assinaturas a partir das informações do assinante.
     *
     * @param certificado certificado do assinante.
     * @return Objeto que representa o verificador de assinaturas.
     */
    private SignerInformationVerifier geraVerificadorInformacoesAssinatura(X509Certificate certificado) {
        try {
            JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();
            SignerInformationVerifier verificador = builder.build(certificado);
            System.out.println("    Sucesso em gerar verificador");
            return verificador;
        } catch (OperatorCreationException e) {
            System.err.println("Erro ao buildar o verificador de assinaturam em VerificadorDeAssinatura: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Classe responsável por pegar as informações da assinatura dentro do CMS.
     *
     * @param assinatura documento assinado.
     * @return Informações da assinatura.
     */
    private SignerInformation pegaInformacoesAssinatura(CMSSignedData assinatura) {
        SignerInformationStore sigInfoStore = assinatura.getSignerInfos();
        Collection<SignerInformation> assinadores = sigInfoStore.getSigners();
        SignerInformation sigInfo = assinadores.iterator().next();
        System.out.println("    Sucesso em coletar informações do assinante");
        return sigInfo;
    }

}
