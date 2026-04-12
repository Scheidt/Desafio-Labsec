package br.ufsc.labsec.pbad.selectionchallengepsc.model;

import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class Session {
    @Id
    private String code;

    private String state;

    private String token;

    @ManyToOne
    private Application application;

    private Long lifetime;

    @Column(updatable = false, nullable = false)
    private LocalDateTime startTime;

    @PrePersist
    public void onCreate() {
        this.startTime = LocalDateTime.now();
    }

    public boolean isExpired() {
        throw new ImplementMeException("Verifique se a sessão expirou com base no tempo de vida e na hora de início");
    }
}
