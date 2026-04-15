package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Data;

import java.util.List;

@Data
public class ApplicationRequest {
    private String name;
    private String email;
    private String comments;
    private List<String> redirectUris;
}
