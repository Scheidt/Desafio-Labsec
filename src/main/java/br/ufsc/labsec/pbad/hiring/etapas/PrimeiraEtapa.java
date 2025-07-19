package br.ufsc.labsec.pbad.hiring.etapas;

import java.nio.file.Path;
import java.nio.file.Paths;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.resumo.Resumidor;


/**
 * <b>Primeira etapa - obter o resumo criptográfico de um documento</b>
 * <p>
 * Basta obter o resumo criptográfico do documento {@code textoPlano.txt}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * obter o resumo criptográfico do documento, especificado na descrição
 * dessa etapa, usando o algoritmo de resumo criptográfico conhecido por
 * SHA-256;
 * </li>
 * <li>
 * armazenar em disco o arquivo contendo o resultado do resumo criptográfico,
 * em formato hexadecimal.
 * </li>
 * </ul>
 */
public class PrimeiraEtapa {

    public static void executarEtapa() {
        Path caminhoTexto = Paths.get(Constantes.caminhoTextoPlano);
        Path caminhoOutput = Paths.get(Constantes.caminhoResumoCriptografico);

        Resumidor resumidor = new Resumidor();
        byte[] resumo = resumidor.resumir(caminhoTexto);
        resumidor.escreveResumoEmDisco(resumo, caminhoOutput);
        System.out.print("Sucesso na Etapa 1!");
    }


}

