package br.ufsc.labsec.pbad.selectionchallengepsc.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Application {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    private String name;
    private String comments;
    @ElementCollection
    @CollectionTable(name = "application_redirect_uris", joinColumns = @JoinColumn(name = "application_id"))
    private List<String> redirectUris;
    private String email;

    private String clientId;
    private String clientSecret;
}
