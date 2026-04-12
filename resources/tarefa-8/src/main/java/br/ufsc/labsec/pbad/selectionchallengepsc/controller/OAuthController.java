package br.ufsc.labsec.pbad.selectionchallengepsc.controller;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.*;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import br.ufsc.labsec.pbad.selectionchallengepsc.service.ApplicationService;
import br.ufsc.labsec.pbad.selectionchallengepsc.service.DiscoveryService;
import br.ufsc.labsec.pbad.selectionchallengepsc.service.OAuthService;
import br.ufsc.labsec.pbad.selectionchallengepsc.service.SignatureService;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequestMapping("/oauth")
@AllArgsConstructor
public class OAuthController {
    private OAuthService oAuthService;
    private ApplicationService applicationService;
    private SignatureService signatureService;
    private DiscoveryService discoveryService;

    @GetMapping(
            path = "/authorize",
            consumes = MediaType.ALL_VALUE,
            produces  = MediaType.TEXT_HTML_VALUE
    )
    public ModelAndView authorize(@RequestParam(name = "response_type") String responseType,
                            @RequestParam(name = "client_id") String clientId,
                            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
                            @RequestParam(required = false) String state,
                            @RequestParam(required = false) Integer lifetime,
                            @RequestParam(required = false) String scope,
                            @RequestParam(name = "code_challenge") String codeChallenge,
                            @RequestParam(name = "code_challenge_method") String codeChallengeMethod,
                            @RequestParam(name = "login_hint", required = false) String loginHint) {
        if (state == null) {
            throw new ImplementMeException("Implemente a geração do state");
        }

        // TODO - ImplementMe Implemente a lógica de autorização

        ModelAndView model = new ModelAndView("authorize");
        model.addObject("state", state);
        model.addObject("userId", loginHint);
        return model;
    }

    @PostMapping(
            path = "/token",
            consumes = "application/x-www-form-urlencoded",
            produces = "application/json"
    )
    public TokenResponse token(TokenRequest tokenRequest) {
        return oAuthService.token(tokenRequest);
    }

    @PostMapping(
            path = "/signature",
            consumes = "application/json",
            produces = "application/json"
    )
    public SignatureResponse signature(SignatureRequest signatureRequest) {
        return signatureService.sign(signatureRequest);
    }

    @PostMapping(
            path = "/application",
            consumes = "application/json",
            produces = "application/json"
    )
    public ApplicationResponse application(ApplicationRequest application) {
        return applicationService.register(application);
    }

    @GetMapping(
            path = "/user-discovery",
            consumes = "application/json",
            produces = "application/json"
    )
    public UserDiscoveryResponse userDiscovery(UserDiscoveryRequest discoveryRequest) {
        return discoveryService.userDiscovery(discoveryRequest);
    }
    
    @GetMapping(
            path = "/certificate-discovery",
            consumes = "application/json",
            produces = "application/json"
    )
    public CertificateDiscoveryResponse certificateDiscovery(CertificateDiscoveryRequest discoveryRequest) {
        return discoveryService.certificateDiscovery(discoveryRequest);
    }
    
}
