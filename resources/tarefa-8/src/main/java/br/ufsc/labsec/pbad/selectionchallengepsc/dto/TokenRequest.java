package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Data;

@Data
public class TokenRequest {
    private String grantType;
    private String clientId;
    private String clientSecret;
    private String code;
    private String redirectUri;
    private String codeVerifier;
}
