package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Getter;

import java.util.List;

@Getter
public class ApplicationRequest {
    private String name;
    private String email;
    private String comments;
    private List<String> redirectUris;
}
