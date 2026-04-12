package br.ufsc.labsec.pbad.selectionchallengepsc.dto;

import lombok.Data;

import java.util.List;

@Data
public class UserDiscoveryResponse {
    private String status;
    private List<CertificateSlot> slots;
}
