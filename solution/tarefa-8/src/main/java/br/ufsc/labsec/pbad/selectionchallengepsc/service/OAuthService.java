package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.AuthorizeRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.AuthorizeResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.TokenRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.TokenResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.InvalidRequestException;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.NotFoundException;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.Application;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.Session;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.ApplicationRepository;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.SessionRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@AllArgsConstructor
public class OAuthService {

    private static final List<String> SUPPORTED_SCOPES = List.of("single_signature", "multi_signature");
    private static final long DEFAULT_LIFETIME_SECONDS = 300L;

    private ApplicationRepository applicationRepository;
    private SessionRepository sessionRepository;

    /**
     * Valida a requisição de autorização OAuth e cria uma Session com código de autorização.
     * Implementa o fluxo Authorization Code com PKCE (RFC 7636).
     *
     * @param request Dados da requisição de autorização
     * @return AuthorizeResponse com o código de autorização e state
     */
    public AuthorizeResponse authorize(AuthorizeRequest request) {
        if (!"code".equals(request.getResponseType())) {
            throw new InvalidRequestException("response_type deve ser 'code'");
        }
        if (!"S256".equals(request.getCodeChallengeMethod())) {
            throw new InvalidRequestException("code_challenge_method deve ser 'S256'");
        }
        if (request.getCodeChallenge() == null || request.getCodeChallenge().isBlank()) {
            throw new InvalidRequestException("code_challenge é obrigatório");
        }
        if (request.getScope() != null && !SUPPORTED_SCOPES.contains(request.getScope())) {
            throw new InvalidRequestException("scope inválido. Valores aceitos: " + SUPPORTED_SCOPES);
        }

        Application application = applicationRepository.findByClientId(request.getClientId())
                .orElseThrow(() -> new NotFoundException("client_id não encontrado"));

        String requestedUri = request.getRedirectUri();
        if (requestedUri != null && !application.getRedirectUris().contains(requestedUri)) {
            throw new InvalidRequestException("redirect_uri não está registrada para esta aplicação");
        }
        String redirectUri = (requestedUri != null) ? requestedUri
                : application.getRedirectUris().get(0);

        long lifetime = (request.getLifetime() != null && request.getLifetime() > 0)
                ? request.getLifetime()
                : DEFAULT_LIFETIME_SECONDS;

        Session session = new Session();
        session.setCode(UUID.randomUUID().toString());
        session.setState(request.getState());
        session.setApplication(application);
        session.setCodeChallenge(request.getCodeChallenge());
        session.setScope(request.getScope());
        session.setRedirectUri(redirectUri);
        session.setLifetime(lifetime);

        sessionRepository.save(session);

        return new AuthorizeResponse(session.getCode(), session.getState());
    }

    /**
     * Troca o código de autorização por um token de acesso.
     * Valida PKCE (S256) conforme RFC 7636.
     *
     * @param request Dados da requisição de token
     * @return TokenResponse com access_token e informações do usuário autorizado
     */
    public TokenResponse token(TokenRequest request) {
        if (!"authorization_code".equals(request.getGrantType())) {
            throw new InvalidRequestException("grant_type deve ser 'authorization_code'");
        }

        Application application = applicationRepository
                .findByClientIdAndClientSecret(request.getClientId(), request.getClientSecret())
                .orElseThrow(() -> new InvalidRequestException("client_id ou client_secret inválidos"));

        Session session = sessionRepository.findById(request.getCode())
                .orElseThrow(() -> new InvalidRequestException("Código de autorização não encontrado"));

        if (!session.getApplication().getId().equals(application.getId())) {
            throw new InvalidRequestException("Código de autorização não pertence a esta aplicação");
        }
        if (session.isExpired()) {
            throw new InvalidRequestException("Código de autorização expirado");
        }
        if (session.getToken() != null) {
            throw new InvalidRequestException("Código de autorização já utilizado");
        }
        if (session.getUser() == null) {
            throw new InvalidRequestException("Autorização ainda não concedida pelo usuário");
        }

        if (request.getRedirectUri() != null
                && !request.getRedirectUri().equals(session.getRedirectUri())) {
            throw new InvalidRequestException("redirect_uri não corresponde ao da autorização");
        }

        validatePkce(request.getCodeVerifier(), session.getCodeChallenge());

        String accessToken = UUID.randomUUID().toString();
        session.setToken(accessToken);
        sessionRepository.save(session);

        return new TokenResponse(
                accessToken,
                "Bearer",
                session.getLifetime().intValue(),
                session.getScope(),
                "CPF",
                session.getUser().getCpf()
        );
    }

    /**
     * Valida o code_verifier PKCE: BASE64URL(SHA-256(verifier)) deve igualar o code_challenge armazenado.
     */
    private void validatePkce(String codeVerifier, String storedChallenge) {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new InvalidRequestException("code_verifier é obrigatório");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            if (!computed.equals(storedChallenge)) {
                throw new InvalidRequestException("code_verifier inválido (PKCE falhou)");
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 não disponível", e);
        }
    }
}
