package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.GeradorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSSignedData;

/**
 * <b>Quinta etapa - gerar uma assinatura digital</b>
 * <p>
 * Essa etapa é um pouco mais complexa, pois será necessário que
 * implemente um método para gerar assinaturas digitais. O padrão de
 * assinatura digital adotado será o Cryptographic Message Syntax (CMS).
 * Esse padrão usa a linguagem ASN.1, que é uma notação em binário, assim
 * não será possível ler o resultado obtido sem o auxílio de alguma
 * ferramenta. Caso tenha interesse em ver a estrutura da assinatura
 * gerada, recomenda-se o uso da ferramenta {@code dumpasn1}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um assinatura digital usando o algoritmo de resumo criptográfico
 * SHA-256 e o algoritmo de criptografia assimétrica ECDSA;
 * </li>
 * <li>
 * o assinante será você. Então, use o repositório de chaves recém gerado para
 * seu certificado e chave privada;
 * </li>
 * <li>
 * assinar o documento {@code textoPlano.txt}, onde a assinatura deverá ser do
 * tipo "anexada", ou seja, o documento estará embutido no arquivo de
 * assinatura;
 * </li>
 * <li>
 * gravar a assinatura em disco.
 * </li>
 * </ul>
 */
public class QuintaEtapa {

    public static void executarEtapa() {
        System.out.println("\nInicio Etapa 5");
        RepositorioChaves repo = new RepositorioChaves();
        try {
            repo.abrir(Constantes.caminhoPkcs12Usuario, Constantes.senhaMestre);
            X509Certificate certificado = repo.pegarCertificado();
            PrivateKey chavePrivada = repo.pegarChavePrivada();
            GeradorDeAssinatura assinador = new GeradorDeAssinatura();
            assinador.informaAssinante(certificado, chavePrivada);
            CMSSignedData assinado = assinador.assinar(Constantes.caminhoTextoPlano);
            try (FileOutputStream fileOutput = new FileOutputStream(Constantes.caminhoAssinatura)){
                assinador.escreveAssinatura(fileOutput, assinado);
                System.out.println("Final da etapa 5 (Sucesso é verificado na etapa 6)!");
            } catch (IOException e){
                System.err.println("Erro ao salvar a assinatura no caminho: " + Constantes.caminhoAssinatura);
            }
        } catch (KeyStoreException e) {
            System.err.println("O repositório está vazio, rode as etapas em ordem!");
            e.printStackTrace();
        }
;

    }

}
