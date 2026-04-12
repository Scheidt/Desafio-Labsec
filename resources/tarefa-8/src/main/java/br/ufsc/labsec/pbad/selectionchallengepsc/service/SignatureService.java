package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.SignatureRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.SignatureResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.ImplementMeException;
import org.springframework.stereotype.Service;

@Service
public class SignatureService {
    private static final String INSTRUCTIONS = """
            Implemente a lógica de assinatura de um hash usando a chave privada do slot selecionado. 
            O processo é detalhado na seção 6.4.5.2 do DOC-ICP-17.01
            """;
    public SignatureResponse sign(SignatureRequest request) {
        throw new ImplementMeException(INSTRUCTIONS);
    }
}
