package br.ufsc.labsec.pbad.selectionchallengepsc.interceptor;

import br.ufsc.labsec.pbad.selectionchallengepsc.model.Session;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.SessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Optional;

/**
 * Intercepta requisições aos endpoints protegidos (/oauth/signature e /oauth/certificate-discovery)
 * e valida o Bearer token presente no header Authorization.
 *
 * <p>A sessão autenticada é disponibilizada como atributo da requisição ("session")
 * para uso nos serviços subsequentes.</p>
 */
@Component
@AllArgsConstructor
public class BearerTokenInterceptor implements HandlerInterceptor {

    private static final String BEARER_PREFIX = "Bearer ";

    private SessionRepository sessionRepository;

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Authorization header ausente ou formato inválido. Use: Bearer <token>");
            return false;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();

        Optional<Session> sessionOpt = sessionRepository.findByToken(token);
        if (sessionOpt.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token inválido ou não encontrado");
            return false;
        }

        Session session = sessionOpt.get();
        if (session.isExpired()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expirado");
            return false;
        }

        if (session.getUser() == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sessão sem usuário associado");
            return false;
        }

        // Disponibiliza a sessão para os serviços downstream via atributo da requisição
        request.setAttribute("session", session);
        return true;
    }
}
