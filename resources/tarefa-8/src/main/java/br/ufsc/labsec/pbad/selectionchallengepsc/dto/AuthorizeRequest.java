package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Getter;

@Getter
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
