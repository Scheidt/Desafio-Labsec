package br.ufsc.labsec.pbad.selectionchallengepsc.repository;

import br.ufsc.labsec.pbad.selectionchallengepsc.model.PscUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PscUserRepository extends JpaRepository<PscUser, String> {
}
