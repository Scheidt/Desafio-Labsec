package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;

import java.security.cert.X509Certificate;

/**
 * Classe responsável por verificar a integridade de uma assinatura.
 */
public class VerificadorDeAssinatura {

    /**
     * Verifica a integridade de uma assinatura digital no padrão CMS.
     *
     * @param certificado certificado do assinante.
     * @param assinatura  documento assinado.
     * @return {@code true} se a assinatura for íntegra, e {@code false} do
     * contrário.
     */
    public boolean verificarAssinatura(X509Certificate certificado,
                                       CMSSignedData assinatura) {
        // TODO implementar
        return false;
    }

    /**
     * Gera o verificador de assinaturas a partir das informações do assinante.
     *
     * @param certificado certificado do assinante.
     * @return Objeto que representa o verificador de assinaturas.
     */
    private SignerInformationVerifier geraVerificadorInformacoesAssinatura(X509Certificate certificado) {
        // TODO implementar
        return null;
    }

    /**
     * Classe responsável por pegar as informações da assinatura dentro do CMS.
     *
     * @param assinatura documento assinado.
     * @return Informações da assinatura.
     */
    private SignerInformation pegaInformacoesAssinatura(CMSSignedData assinatura) {
        // TODO implementar
        return null;
    }

}
