package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.VerificadorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * <b>Sexta etapa - verificar uma assinatura digital</b>
 * <p>
 * Por último, será necessário verificar a integridade da assinatura
 * recém gerada. Note que o processo de validação de uma assinatura
 * digital pode ser muito complexo, mas aqui o desafio será simples. Para
 * verificar a assinatura será necessário apenas decifrar o valor da
 * assinatura (resultante do processo de cifra do resumo criptográfico do
 * arquivo {@code textoPlano.txt} com as informações da estrutura da
 * assinatura) e comparar esse valor com o valor do resumo criptográfico do
 * arquivo assinado. Como dito na fundamentação, para assinar é usada a chave
 * privada, e para decifrar (verificar) é usada a chave pública.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * verificar a assinatura gerada na etapa anterior, de acordo com o
 * processo descrito, e apresentar esse resultado.
 * </li>
 * </ul>
 */
public class SextaEtapa {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void executarEtapa() {
        System.out.println("\nInicio etapa 6");
        try {
            X509Certificate certificado = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoUsuario);
            byte[] assinaturaBytes = Files.readAllBytes(Paths.get(Constantes.caminhoAssinatura));

            CMSSignedData assinatura = new CMSSignedData(assinaturaBytes);

            VerificadorDeAssinatura verificador = new VerificadorDeAssinatura();

            boolean igual = verificador.verificarAssinatura(certificado, assinatura);
            if (igual) {
                System.out.println("O certificado utilizado para gerar a assinatura da etapa 5 é o do usuário");
                System.out.println("Sucesso na etapa 5!");
                System.out.println("Sucesso na Etapa 6!");
            } else {
                System.err.println("Verificação de assinatura falhou. A assinatura pode ser inválida ou o certificado incorreto.");
            }

        } catch (IOException | CertificateException | CMSException | OperatorCreationException e) {
            System.err.println("Ocorreu um erro na sexta etapa: " + e.getMessage());
        }
    }

}
