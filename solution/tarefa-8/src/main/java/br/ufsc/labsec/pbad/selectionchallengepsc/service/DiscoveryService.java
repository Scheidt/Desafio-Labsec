package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.*;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.InvalidRequestException;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.NotFoundException;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.PscUser;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.Session;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.ApplicationRepository;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.PscUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Base64;
import java.util.List;

@Service
@AllArgsConstructor
public class DiscoveryService {

    private PscUserRepository pscUserRepository;
    private ApplicationRepository applicationRepository;

    /**
     * Descobre o usuário e lista seus slots de certificado.
     * Requer autenticação via clientId + clientSecret da aplicação.
     *
     * @param request Requisição com clientId, clientSecret e CPF/CNPJ do usuário
     * @return Lista de slots (alias + label) de certificados do usuário
     */
    public UserDiscoveryResponse userDiscovery(UserDiscoveryRequest request) {
        if (request.getClientId() == null || request.getClientSecret() == null) {
            throw new InvalidRequestException("clientId e clientSecret são obrigatórios");
        }

        applicationRepository
                .findByClientIdAndClientSecret(request.getClientId(), request.getClientSecret())
                .orElseThrow(() -> new InvalidRequestException("clientId ou clientSecret inválidos"));

        if (request.getUserCpfCnpj() == null || request.getUserCpfCnpj().isBlank()) {
            throw new InvalidRequestException("userCpfCnpj é obrigatório");
        }

        PscUser user = pscUserRepository.findByCpf(request.getUserCpfCnpj())
                .orElseThrow(() -> new NotFoundException(
                        "Usuário não encontrado para o CPF/CNPJ: " + request.getUserCpfCnpj()));

        List<CertificateSlot> slots = user.getCertificates().stream()
                .map(cert -> {
                    CertificateSlot slot = new CertificateSlot();
                    slot.setSlotAlias(cert.getAlias());
                    slot.setLabel(cert.getLabel());
                    return slot;
                })
                .toList();

        UserDiscoveryResponse resp = new UserDiscoveryResponse();
        resp.setStatus("success");
        resp.setSlots(slots);
        return resp;
    }

    /**
     * Retorna os certificados disponíveis para o usuário autenticado via Bearer token.
     * O filtro por alias é opcional; sem alias retorna todos os certificados.
     *
     * @param request Requisição com alias do certificado (opcional)
     * @return Lista de certificados em formato Base64 DER
     */
    public CertificateDiscoveryResponse certificateDiscovery(CertificateDiscoveryRequest request) {
        Session session = getSessionFromRequest();
        PscUser user = session.getUser();

        List<Certificate> certificates = user.getCertificates().stream()
                .filter(cert -> request.getCertificateAlias() == null
                        || cert.getAlias().equalsIgnoreCase(request.getCertificateAlias()))
                .map(cert -> {
                    Certificate dto = new Certificate();
                    dto.setAlias(cert.getAlias());
                    dto.setLabel(cert.getLabel());
                    dto.setCertificate(Base64.getEncoder().encodeToString(cert.getCertificate()));
                    return dto;
                })
                .toList();

        if (certificates.isEmpty()) {
            throw new NotFoundException("Nenhum certificado encontrado para o alias: "
                    + request.getCertificateAlias());
        }

        CertificateDiscoveryResponse resp = new CertificateDiscoveryResponse();
        resp.setStatus("success");
        resp.setCertificates(certificates);
        return resp;
    }

    /** Recupera a sessão autenticada injetada pelo {@link br.ufsc.labsec.pbad.selectionchallengepsc.interceptor.BearerTokenInterceptor}. */
    private Session getSessionFromRequest() {
        HttpServletRequest httpRequest =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        Session session = (Session) httpRequest.getAttribute("session");
        if (session == null) {
            throw new InvalidRequestException("Sessão não encontrada na requisição");
        }
        return session;
    }
}
