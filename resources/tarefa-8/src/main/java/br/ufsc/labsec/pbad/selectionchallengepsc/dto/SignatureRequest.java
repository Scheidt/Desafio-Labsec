package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Getter;

import java.util.List;

@Getter
public class SignatureRequest {
    private String certificateAlias;
    private List<TbsHash> hashes;
}
