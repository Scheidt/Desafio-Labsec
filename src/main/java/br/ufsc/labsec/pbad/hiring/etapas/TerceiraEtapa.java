package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * <b>Terceira etapa - gerar certificados digitais</b>
 * <p>
 * Aqui você terá que gerar dois certificados digitais. A identidade ligada
 * a um dos certificados digitais deverá ser a sua. A entidade emissora do
 * seu certificado será a AC-Raiz, cuja chave privada já foi previamente
 * gerada. Também deverá ser feito o certificado digital para a AC-Raiz,
 * que deverá ser autoassinado.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * emitir um certificado digital autoassinado no formato X.509 para a AC-Raiz;
 * </li>
 * <li>
 * emitir um certificado digital no formato X.509, assinado pela AC-Raiz. O
 * certificado deve ter as seguintes características:
 * <ul>
 * <li>
 * {@code Subject} deverá ser o seu nome;
 * </li>
 * <li>
 * {@code SerialNumber} deverá ser o número da sua matrícula;
 * </li>
 * <li>
 * {@code Issuer} deverá ser a AC-Raiz.
 * </li>
 * </ul>
 * </li>
 * <li>
 * anexar ao desafio os certificados emitidos em formato PEM;
 * </li>
 * <li>
 * as chaves utilizadas nessa etapa deverão ser as mesmas já geradas.
 * </li>
 * </ul>
 */
public class TerceiraEtapa {

    public static void executarEtapa() {
        System.out.println("\nInício Etapa 3");
        try {
            // Carrega chaves necessárias
            PrivateKey privadaAc = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc, Constantes.algoritmoChave);
            PublicKey publicaAc = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaAc, Constantes.algoritmoChave);
            PublicKey publicaUsuario = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaUsuario, Constantes.algoritmoChave);

            // Gera os certificados
            GeradorDeCertificados geradorCert = new GeradorDeCertificados();

            X509Certificate certificadoCA = geradorCert.gerarCertificado(publicaAc,
                    privadaAc,
                    Constantes.numeroSerieAc,
                    Constantes.nomeAcRaiz,
                    Constantes.nomeAcRaiz,
                    10);

            X509Certificate certificadoUsuario = geradorCert.gerarCertificado(publicaUsuario,
                    privadaAc,
                    Constantes.numeroDeSerie,
                    Constantes.nomeUsuario,
                    Constantes.nomeAcRaiz,
                    5);

            // Escreve os certificados em disco
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoAcRaiz, certificadoCA.getEncoded());
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoUsuario, certificadoUsuario.getEncoded());

            // Lê os certificados do disco para verificação
            X509Certificate certificadoCarregadoCa = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoAcRaiz);
            X509Certificate certificadoCarregadoUsuario = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoUsuario);

            // Compara os certificados gerados com os lidos do disco
            if (certificadoCA.equals(certificadoCarregadoCa) && certificadoUsuario.equals(certificadoCarregadoUsuario)) {
                System.out.println("    Verificação de integridade dos certificados concluída com sucesso.");
                System.out.println("Sucesso na etapa 3!");
            } else {
                System.err.println("Falha na verificação: Os certificados escritos em disco não são idênticos aos lidos.");
            }

        } catch (IOException | OperatorCreationException | CertificateException e) {
            System.err.println("Erro ao executar a Terceira Etapa: " + e.getMessage());
        }
    }
}
