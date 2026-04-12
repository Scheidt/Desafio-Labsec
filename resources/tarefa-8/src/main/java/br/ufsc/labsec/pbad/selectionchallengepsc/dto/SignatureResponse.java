package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class SignatureResponse {
    private String certificateAlias;
    private List<Signature> signatures;
}
