package br.ufsc.labsec.pbad.hiring.etapas;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.EscritorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;

/**
 * <b>Segunda etapa - gerar chaves assimétricas</b>
 * <p>
 * A partir dessa etapa, tudo que será feito envolve criptografia assimétrica.
 * A tarefa aqui é parecida com a etapa anterior, pois refere-se apenas a
 * criar e armazenar chaves, mas nesse caso será usado um algoritmo de
 * criptografia assimétrica, o ECDSA.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um par de chaves usando o algoritmo ECDSA com o tamanho de 256 bits;
 * </li>
 * <li>
 * gerar outro par de chaves, mas com o tamanho de 521 bits. Note que esse
 * par de chaves será para a AC-Raiz;
 * </li>
 * <li>
 * armazenar em disco os pares de chaves em formato PEM.
 * </li>
 * </ul>
 */
public class SegundaEtapa {

    public static void executarEtapa() {
        String algoritmo = Constantes.algoritmoChave;
        GeradorDeChaves gerador = new GeradorDeChaves(algoritmo);

        // Gera e escreve as chaves do usuario em disco
        KeyPair chavesUsuario = gerador.gerarParDeChaves(256);

        PublicKey pubKeyUsuario = chavesUsuario.getPublic();
        EscritorDeChaves.escreveChaveEmDisco(pubKeyUsuario, Constantes.caminhoChavePublicaUsuario);
        PrivateKey privateKeyUsuario = chavesUsuario.getPrivate();
        EscritorDeChaves.escreveChaveEmDisco(privateKeyUsuario, Constantes.caminhoChavePrivadaUsuario);

        // Gera e escreve as chaves do AC em disco
        KeyPair chavesAC = gerador.gerarParDeChaves(521);
        PublicKey pubKeyAC = chavesAC.getPublic();
        EscritorDeChaves.escreveChaveEmDisco(pubKeyAC, Constantes.caminhoChavePublicaAc);
        PrivateKey privateKeyAC = chavesAC.getPrivate();
        EscritorDeChaves.escreveChaveEmDisco(privateKeyAC, Constantes.caminhoChavePrivadaAc);
        System.out.println("Sucesso na Etapa 2!");
    }

}
