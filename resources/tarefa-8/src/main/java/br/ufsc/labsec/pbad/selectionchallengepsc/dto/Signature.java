package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Data;

@Data
public class Signature {
    private String rawSignature;
    private String detached;
}
