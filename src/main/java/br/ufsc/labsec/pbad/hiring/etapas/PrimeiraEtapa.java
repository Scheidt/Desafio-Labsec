package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import Java.nio.file.Path;
import Java.nio.file.Paths;
import Java.nio.file.Files;
import Java.util.HexFormat

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

        try {
            MessageDigest hasher = MessageDigest.getInstance(Constantes.algoritmoResumo);

            Path caminhoTexto = Paths.get(Constantes.caminhoTextoPlano);
            Path caminhoOutput = Paths.get(Constantes.caminhoResumoCriptografico);

            byte[] bytesTextoPlano = Files.readAllBytes(caminhoTexto);

            byte[] hashed = hasher.digest(bytesTextoPlano);

            String hashHex = hashPraHex(hashed);

            Files.createDirectories(caminhoOutput.getParent());
            Files.write(caminhoOutput, hashHex.getBytes());

            System.out.println("Sucesso na primeira etapa :)");

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }


    public static String hashPraHex (byte[] hash){
        HexFormat hexFormat = HexFormat.of();
        return hexFormat.formatHex(hash);
    }

}


/**
    public static final String caminhoTextoPlano =
            caminhoArtefatos + "textos/textoPlano.txt";
    public static final String caminhoResumoCriptografico =
            caminhoArtefatos + "resumos/resumoTextoPlano.hex";
*/