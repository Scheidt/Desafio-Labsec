package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.CertificateDiscoveryRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.CertificateDiscoveryResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.UserDiscoveryRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.UserDiscoveryResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.PscUserRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class DiscoveryService {
     private static final String INSTRUCTIONS = """
             Nesta classe você deve implementar as funcionalidades de descoberta de usuários e certificados. 
             Você deve utilizar o UserRepository para acessar os dados dos usuários e certificados. 
             """;

     private PscUserRepository pscUserRepository;

    public UserDiscoveryResponse userDiscovery(UserDiscoveryRequest discoveryRequest) {
        throw new ImplementMeException(INSTRUCTIONS);
    }

    public CertificateDiscoveryResponse certificateDiscovery(CertificateDiscoveryRequest discoveryRequest) {
        throw new ImplementMeException(INSTRUCTIONS);
    }
}
