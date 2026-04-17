package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizeRequest {
    private String responseType;
    private String clientId;
    private String redirectUri;
    private String state;
    private Integer lifetime;
    private String scope;
    private String codeChallenge;
    private String codeChallengeMethod;
    private String loginHint;
}
