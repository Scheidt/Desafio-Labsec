package br.ufsc.labsec.pbad.selectionchallengepsc.repository;

import br.ufsc.labsec.pbad.selectionchallengepsc.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, String> {

    Optional<Session> findByToken(String token);

    Optional<Session> findByState(String state);
}
