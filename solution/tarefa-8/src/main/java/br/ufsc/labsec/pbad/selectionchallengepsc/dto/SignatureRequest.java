package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Data;

import java.util.List;

@Data
public class SignatureRequest {
    private String certificateAlias;
    private List<TbsHash> hashes;
}
