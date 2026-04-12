package br.ufsc.labsec.pbad.selectionchallengepsc.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Data
public class PscUser {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Setter(AccessLevel.NONE)
    private String id;
    private String name;
    private String cpf;
    private String defaultCertificateAlias;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_certificates", joinColumns = @JoinColumn(name = "user_id"))
    @Setter(AccessLevel.NONE)
    private List<UserCertificate> certificates;


    @Embeddable
    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    public static final class UserCertificate {
        private String label;
        private String alias;
        @Column(columnDefinition = "BYTEA")
        private byte[] certificate;
        @Column(columnDefinition = "BYTEA")
        private byte[] privateKey;
    }
}
