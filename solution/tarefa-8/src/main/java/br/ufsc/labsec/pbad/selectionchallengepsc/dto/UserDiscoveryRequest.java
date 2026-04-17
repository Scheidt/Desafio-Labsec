package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Data;

@Data
public class UserDiscoveryRequest {
    private String clientId;
    private String clientSecret;
    private String userCpfCnpj;
    private String valCpfCnpj;
}
