package br.ufsc.labsec.pbad.selectionchallengepsc.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class Session {
    @Id
    private String code; // Código de autorização gerado no /oauth/authorize, usado para obter o token no /oauth/token.

    private String state; // Proteção contra CSRF, recebido no /oauth/authorize e retornado no /oauth/token.

    private String token; // Token de acesso gerado no /oauth/token, retornado para a aplicação cliente e usado para autenticar as requisições de assinatura.

    @ManyToOne
    private Application application; // Aplicação cliente associada a esta sessão (identificada pelo client_id na autorização).

    @ManyToOne
    private PscUser user; // Usuário PSC associado a esta sessão (identificado pelo CPF do usuário na autorização).

    private Long lifetime; // Tempo de vida da sessão em segundos, recebido no /oauth/authorize e usado para determinar a expiração da sessão.

    private String codeChallenge; // code_challenge (S256) recebido no /oauth/authorize, usado na validação PKCE do /oauth/token.

    private String scope;// Escopo solicitado na autorização (single_signature ou multi_signature).

    private String redirectUri; // URI de redirecionamento solicitada no /oauth/authorize.

    @Column(updatable = false, nullable = false)
    private LocalDateTime startTime;

    @PrePersist
    public void onCreate() {
        this.startTime = LocalDateTime.now();
    }

    /**
     * Verifica se a sessão expirou com base no tempo de vida (em segundos) e na hora de início.
     * @return true se a sessão estiver expirada, false caso contrário
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(startTime.plusSeconds(lifetime));
    }
}
