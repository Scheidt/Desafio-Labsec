package br.ufsc.labsec.pbad.selectionchallengepsc.repository;

import br.ufsc.labsec.pbad.selectionchallengepsc.model.Application;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ApplicationRepository extends JpaRepository<Application, String> {

    Optional<Application> findByClientId(String clientId);

    Optional<Application> findByClientIdAndClientSecret(String clientId, String clientSecret);
}
