package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.GeradorDeRepositorios;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * <b>Quarta etapa - gerar repositório de chaves seguro</b>
 * <p>
 * Essa etapa tem como finalidade gerar um repositório seguro de chaves
 * assimétricas. Esse repositório deverá ser no formato PKCS#12. Note que
 * esse repositório é basicamente um tabela de espalhamento com pequenas
 * mudanças. Por exemplo, sua estrutura seria algo como {@code <Alias,
 * <Certificado, Chave Privada>>}, onde o _alias_ é um nome amigável dado a
 * uma entrada da estrutura, e o certificado e chave privada devem ser
 * correspondentes à mesma identidade. O _alias_ serve como elemento de busca
 * dessa identidade. O PKCS#12 ainda conta com uma senha, que serve para
 * cifrar a estrutura (isso é feito de modo automático).
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um repositório para o seu certificado/chave privada com senha e
 * alias de acordo com as constantes fornecidas;
 * </li>
 * <li>
 * gerar um repositório para o certificado/chave privada da AC-Raiz com senha
 * e alias de acordo com as constantes fornecidas.
 * </li>
 * </ul>
 */
public class QuartaEtapa {

    public static void executarEtapa() {
        System.out.println("\nInício Etapa 4");
        try {
            // Carrega as chaves e certificados do disco
            PrivateKey privadaAc = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc, Constantes.algoritmoChave);
            X509Certificate certificadoAc = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoAcRaiz);
            PrivateKey privadaUsuario = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaUsuario, Constantes.algoritmoChave);
            X509Certificate certificadoUsuario = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoUsuario);

            // Gera e salva os repositórios PKCS#12
            GeradorDeRepositorios.gerarPkcs12(privadaAc, certificadoAc, Constantes.caminhoPkcs12AcRaiz, Constantes.aliasAc, Constantes.senhaMestre);
            GeradorDeRepositorios.gerarPkcs12(privadaUsuario, certificadoUsuario, Constantes.caminhoPkcs12Usuario, Constantes.aliasUsuario, Constantes.senhaMestre);

            // Sessão de verificação
            boolean acIguais = false;
            boolean usuarioIguais = false;

            // Abre e verifica o repositório da AC-Raiz
            RepositorioChaves repositorioAc = new RepositorioChaves();
            repositorioAc.abrir(Constantes.caminhoPkcs12AcRaiz, Constantes.senhaMestre);
            if (privadaAc.equals(repositorioAc.pegarChavePrivada()) &&
                    certificadoAc.equals(repositorioAc.pegarCertificado())) {
                acIguais = true;
            } else {
                System.err.println("Falha na verificação do PKCS#12 da AC-Raiz.");
            }

            // Abre e verifica o repositório do Usuário
            RepositorioChaves repositorioUsuario = new RepositorioChaves();
            repositorioUsuario.abrir(Constantes.caminhoPkcs12Usuario, Constantes.senhaMestre);
            if (privadaUsuario.equals(repositorioUsuario.pegarChavePrivada()) &&
                    certificadoUsuario.equals(repositorioUsuario.pegarCertificado())) {
                usuarioIguais = true;
            } else {
                System.err.println("Falha na verificação do PKCS#12 do Usuário.");
            }

            if (acIguais && usuarioIguais) {
                System.out.println("Sucesso na etapa 4!");
            }

        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | NoSuchProviderException | UnrecoverableKeyException e) {
            System.err.println("Erro ao executar a Quarta Etapa: " + e.getMessage());
        }
    }
}
