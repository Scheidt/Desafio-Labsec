package br.ufsc.labsec.pbad.selectionchallengepsc.configuration;

import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.PscUser;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.PscUserRepository;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@Log4j2
@AllArgsConstructor
public class LoadDatabase {

    private PscUserRepository pscUserRepository;

    private static final String INSTRUCTIONS = """
            Implemente o método initDatabase() para carregar a base de dados com os seguintes dados iniciais:
            - Usuário 1:
                - name: "{Primeiro Nome}-{seu IdUfsc}"
                - cpf: "{seu CPF}"
                - defaultCertificateAlias: "RSA"
            - Usuário 2:
                - name: "{Primeiro Nome}-{seu IdUfsc}-PQC"
                - cpf: "{seu CPF} + 1"
                - defaultCertificateAlias: "MLDSA"
            Para cada usuário gerar dois pares de chaves acompanhados do respectivo certificado.
               - 1 par de chaves para o algoritmo RSA 2048 bits
               - 1 par de chaves para o algoritmo MLDSA 87
            Os certificados devem ser assinados pela chave disponível em https://pbad.labsec.ufsc.br/challenge/artifacts/rsa/AUTOMATIC_LOVE.p12
               - A senha da keystore é "1234"
               - O subject de cada certificado deve ser: CN={name}, OU=PBAD, O=UFSC, C=BR
               - alias: {RSA ou MLDSA}
               - label: Certificado {RSA ou MLDSA} do usuário {name}
            """;

    /**
     * Carrega a base de dados com os usuários iniciais da aplicação. Os dados a serem carregados estão descritos na constante INSTRUCTIONS.
     * @see PscUser
     * @see PscUserRepository
     */
    @EventListener(ApplicationReadyEvent.class)
    public void initDatabase() {
        log.info("Loading database with initial data...");
        throw new ImplementMeException(INSTRUCTIONS);
    }
}
