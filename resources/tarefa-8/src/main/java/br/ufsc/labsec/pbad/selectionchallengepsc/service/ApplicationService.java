package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.ApplicationRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.ApplicationResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.ApplicationRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ApplicationService {
    private static final String INSTRUCTIONS = """
            Implemente o endpoint de registro de aplicação.
            Ele deve receber um objeto do tipo ApplicationRequestDTO,
            validar os dados, criar uma Application e retornar um ApplicationDTO.
            Lembre-se de tratar possíveis erros e retornar respostas adequadas para cada caso.
            """;

    private ApplicationRepository applicationRepository;

    /**
     * Registra uma nova aplicação.
     * @see br.ufsc.labsec.pbad.selectionchallengepsc.repository.ApplicationRepository
     * @param application dados da aplicação a ser registrada
     * @return dados da aplicação registrada
     */
    public ApplicationResponse register(ApplicationRequest application) {
        throw new ImplementMeException(INSTRUCTIONS);
    }
}
