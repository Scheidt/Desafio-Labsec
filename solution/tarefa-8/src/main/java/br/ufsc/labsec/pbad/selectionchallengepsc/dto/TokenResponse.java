package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String tokenType;
    private Integer expiresIn;
    private String scope;
    private String authorizedIdentificationType;
    private String authorizedIdentification;
}
