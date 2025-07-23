package br.ufsc.labsec.pbad.hiring.etapas;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;


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

        PrivateKey privadaAc = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc, Constantes.algoritmoChave);
        PublicKey publicaAc = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaAc, Constantes.algoritmoChave);

        @SuppressWarnings("unused")
        PrivateKey privadaUsuario = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaUsuario, Constantes.algoritmoChave);
        PublicKey publicaUsuario = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaUsuario, Constantes.algoritmoChave);


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

        

        // Sessão do código dedicada a debugging
        int sucessos = 0;
        // importante verificar se os certificados salvos são iguais aos certificados que serão carregados posteriormente
        // caso não forem, houve algum erro na hora de salvar ou de carregar do disco
        int iguais = 0;

        try {
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoAcRaiz, certificadoCA.getEncoded());
            sucessos += 1;
            X509Certificate certificadoCarregadoCa = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoAcRaiz);
            if (certificadoCA.equals(certificadoCarregadoCa)){
                iguais += 1;
            }

        } catch (CertificateEncodingException e) {
            System.err.println("Erro ao escrever o certificado CA em disco, erro ao converter certificado para Bytes[]");
            e.printStackTrace();
        }

        try {
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoUsuario, certificadoUsuario.getEncoded());
            sucessos = sucessos + 1;
            X509Certificate certificadoCarregadoUsuario = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoUsuario);
            if (certificadoUsuario.equals(certificadoCarregadoUsuario)){
                iguais += 1;
            }
        } catch (CertificateEncodingException e) {
            System.err.println("Erro ao escrever o certificado do usuario em disco, erro ao converter certificado para Bytes[]");
            e.printStackTrace();
        }

        if (sucessos == 2) {
            System.out.println("    Certificados Salvos");
            if (iguais == 2) {
                System.out.println("    Certificados carregados são iguais aos salvos");
                System.out.println("Sucesso na etapa 3!");
            } else {
                System.out.println("Numero de certificados iguais aos carregados: " + iguais);
            }
        }

    }

}
