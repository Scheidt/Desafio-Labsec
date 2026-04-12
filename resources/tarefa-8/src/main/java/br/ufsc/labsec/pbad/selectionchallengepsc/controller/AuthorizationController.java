package br.ufsc.labsec.pbad.selectionchallengepsc.controller;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/authorization")
@AllArgsConstructor
public class AuthorizationController {
    @PostMapping("/{userId}/accept")
    public RedirectView accept(@PathVariable String userId, String state) {
        // TODO - ImplementMe Lógica de aceitação
        // TODO obter redirectUrl a partir do userId
        // TODO gerar code de autorização
        String code = "";
        return new RedirectView("/redirect/" + userId + "?state=" + (state != null ? state : "") + "&code=" + code);
    }

    @PostMapping("/{userId}/reject")
    public RedirectView reject(@PathVariable String userId, String state) {
        // TODO - ImplementMe Lógica de rejeição
        // TODO obter redirectUrl a partir do userId
        return new RedirectView("/redirect/" + userId + "?state=" + (state != null ? state : ""));
    }
}
