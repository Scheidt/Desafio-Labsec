package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Getter;

@Getter
public class TbsHash {
    private String id;
    private String alias;
    private String hash;
    private String hashAlgorithm;
    private String signatureFormat;
}
