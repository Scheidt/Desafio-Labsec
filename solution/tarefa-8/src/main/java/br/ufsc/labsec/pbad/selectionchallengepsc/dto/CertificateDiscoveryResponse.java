package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Data;

import java.util.List;

@Data
public class CertificateDiscoveryResponse {
    private String status;
    private List<Certificate> certificates;
}
