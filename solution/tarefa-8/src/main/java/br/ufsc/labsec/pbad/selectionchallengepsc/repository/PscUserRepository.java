package br.ufsc.labsec.pbad.selectionchallengepsc.repository;

import br.ufsc.labsec.pbad.selectionchallengepsc.model.PscUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PscUserRepository extends JpaRepository<PscUser, String> {

    Optional<PscUser> findByCpf(String cpf);
}
