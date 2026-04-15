package br.ufsc.labsec.pbad.selectionchallengepsc.controller;

import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.InvalidRequestException;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.NotFoundException;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.PscUser;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.Session;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.PscUserRepository;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.SessionRepository;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/authorization")
@AllArgsConstructor
public class AuthorizationController {

    private SessionRepository sessionRepository;
    private PscUserRepository pscUserRepository;

    /**
     * Processa a aceitação da autorização pelo usuário.
     * Associa o usuário à sessão e redireciona para a redirect_uri com o código de autorização.
     */
    @PostMapping("/{userId}/accept")
    public RedirectView accept(@PathVariable String userId,
                               @RequestParam String state) {
        Session session = sessionRepository.findByState(state)
                .orElseThrow(() -> new NotFoundException("Sessão não encontrada para o state fornecido"));

        if (session.isExpired()) {
            throw new InvalidRequestException("Sessão expirada");
        }

        PscUser user = pscUserRepository.findByCpf(userId)
                .orElseThrow(() -> new NotFoundException("Usuário com CPF '" + userId + "' não encontrado"));

        session.setUser(user);
        sessionRepository.save(session);

        String redirectUri = session.getRedirectUri();
        String code = session.getCode();
        return new RedirectView(redirectUri + "?code=" + code + "&state=" + state);
    }

    /**
     * Processa a rejeição da autorização pelo usuário.
     * Redireciona para a redirect_uri com indicação de erro.
     */
    @PostMapping("/{userId}/reject")
    public RedirectView reject(@PathVariable String userId,
                               @RequestParam String state) {
        Session session = sessionRepository.findByState(state)
                .orElseThrow(() -> new NotFoundException("Sessão não encontrada para o state fornecido"));

        String redirectUri = session.getRedirectUri();
        return new RedirectView(redirectUri + "?error=access_denied&state=" + state);
    }
}
