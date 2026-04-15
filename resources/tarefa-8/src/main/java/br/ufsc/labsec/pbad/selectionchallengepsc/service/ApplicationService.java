package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.ApplicationRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.ApplicationResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.Application;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.ApplicationRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@AllArgsConstructor
public class ApplicationService {

    private ApplicationRepository applicationRepository;

    /**
     * Registra uma nova aplicação OAuth gerando clientId e clientSecret únicos.
     *
     * @param request Dados da aplicação a ser registrada
     * @return Resposta com clientId, clientSecret e status da operação
     */
    public ApplicationResponse register(ApplicationRequest request) {
        // Retorna erro e não lança exceção para facilitar o tratamento no controller e exibição de mensagens amigáveis para o usuário.
        if (request.getName() == null || request.getName().isBlank()) {
            return new ApplicationResponse(null, null, "error", "O campo 'name' é obrigatório");
        }
        if (request.getEmail() == null || request.getEmail().isBlank()) {
            return new ApplicationResponse(null, null, "error", "O campo 'email' é obrigatório");
        }
        if (request.getRedirectUris() == null || request.getRedirectUris().isEmpty()) {
            return new ApplicationResponse(null, null, "error", "Ao menos um 'redirectUri' é obrigatório");
        }

        String clientId     = UUID.randomUUID().toString();
        String clientSecret = UUID.randomUUID().toString();

        Application app = new Application();
        app.setName(request.getName());
        app.setEmail(request.getEmail());
        app.setComments(request.getComments());
        app.setRedirectUris(request.getRedirectUris());
        app.setClientId(clientId);
        app.setClientSecret(clientSecret);

        applicationRepository.save(app);

        return new ApplicationResponse(clientId, clientSecret, "success", "Aplicação registrada com sucesso");
    }
}
