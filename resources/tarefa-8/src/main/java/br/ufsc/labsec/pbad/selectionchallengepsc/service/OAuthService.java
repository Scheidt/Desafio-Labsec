package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.AuthorizeRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.AuthorizeResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.TokenRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.TokenResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import org.springframework.stereotype.Service;

@Service
public class OAuthService {

    private static final String INSTRUCTIONS_AUTHORIZE = """
            """;
    public static final String INSTRUCTIONS_TOKEN = """
            """;

    public AuthorizeResponse authorize(AuthorizeRequest authorizeRequest) {
        throw new ImplementMeException(INSTRUCTIONS_AUTHORIZE);
    }

    public TokenResponse token(TokenRequest tokenRequest) {
        throw new ImplementMeException(INSTRUCTIONS_TOKEN);
    }
}
