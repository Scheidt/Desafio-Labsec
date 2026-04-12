package br.ufsc.labsec.pbad.selectionchallengepsc.interceptor;

import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.SessionRepository;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.PscUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@AllArgsConstructor
public class BearerTokenInterceptor implements HandlerInterceptor {

    private static final String INSTRUCTIONS = """
            Nesta classe você deve implementar a funcionalidade de interceptação de requisições para verificar a presença e validade do token.
            Você deve utilizar o SessionRepository para acessar os dados das sessões ativas e validar o token.
            """;

    private PscUserRepository pscUserRepository;
    private SessionRepository sessionRepository;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        throw new ImplementMeException(INSTRUCTIONS);
    }
}
