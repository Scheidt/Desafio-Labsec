package br.ufsc.labsec.pbad.selectionchallengepsc.repository;

import br.ufsc.labsec.pbad.selectionchallengepsc.model.Application;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApplicationRepository extends JpaRepository<Application, String> {
}
