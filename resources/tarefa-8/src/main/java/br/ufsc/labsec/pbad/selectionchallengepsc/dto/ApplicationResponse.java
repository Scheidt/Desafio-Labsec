package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

public record ApplicationResponse(String clientId, String clientSecret, String status, String message) {
}
