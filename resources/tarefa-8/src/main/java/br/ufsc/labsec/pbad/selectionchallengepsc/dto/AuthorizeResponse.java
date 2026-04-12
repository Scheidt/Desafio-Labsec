package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthorizeResponse {
    private String code;
    private String state;
}
