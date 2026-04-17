package br.ufsc.labsec.pbad.selectionchallengepsc.service;

import br.ufsc.labsec.pbad.selectionchallengepsc.dto.Signature;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.SignatureRequest;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.SignatureResponse;
import br.ufsc.labsec.pbad.selectionchallengepsc.dto.TbsHash;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.InvalidRequestException;
import br.ufsc.labsec.pbad.selectionchallengepsc.exceptions.NotFoundException;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.PscUser;
import br.ufsc.labsec.pbad.selectionchallengepsc.model.Session;
import br.ufsc.labsec.pbad.selectionchallengepsc.util.SignatureHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Serviço de assinatura digital conforme seção 6.4.5.2 do DOC-ICP-17.01.
 * Suporta apenas formato RAW (não CMS).
 */
@Service
@AllArgsConstructor
public class SignatureService {

    /**
     * Assina a lista de hashes usando a chave privada do certificado indicado.
     * O usuário autenticado é obtido via sessão Bearer token (injetada pelo interceptor).
     *
     * @param request Requisição contendo o alias do certificado e os hashes a assinar
     * @return Resposta com as assinaturas RAW em Base64
     */
    public SignatureResponse sign(SignatureRequest request) {
        if (request.getCertificateAlias() == null || request.getCertificateAlias().isBlank()) {
            throw new InvalidRequestException("certificateAlias é obrigatório");
        }
        if (request.getHashes() == null || request.getHashes().isEmpty()) {
            throw new InvalidRequestException("A lista de hashes não pode ser vazia");
        }

        Session session = getSessionFromRequest();
        PscUser user = session.getUser();

        PscUser.UserCertificate userCert = user.getCertificates().stream()
                .filter(c -> c.getAlias().equalsIgnoreCase(request.getCertificateAlias()))
                .findFirst()
                .orElseThrow(() -> new NotFoundException(
                        "Certificado não encontrado para alias: " + request.getCertificateAlias()));

        PrivateKey privateKey;
        try {
            privateKey = SignatureHelper.loadPrivateKey(userCert.getPrivateKey(), userCert.getCertificate());
        } catch (Exception e) {
            throw new RuntimeException("Falha ao carregar chave privada: " + e.getMessage(), e);
        }

        List<Signature> signatures = new ArrayList<>();
        for (TbsHash tbsHash : request.getHashes()) {
            if (!"RAW".equalsIgnoreCase(tbsHash.getSignatureFormat())) {
                throw new InvalidRequestException(
                        "Formato de assinatura não suportado: " + tbsHash.getSignatureFormat()
                        + ". Apenas RAW é suportado.");
            }

            byte[] hashBytes;
            try {
                hashBytes = Base64.getDecoder().decode(tbsHash.getHash());
            } catch (IllegalArgumentException e) {
                throw new InvalidRequestException(
                        "Hash inválido (não é Base64 válido) para id: " + tbsHash.getId());
            }

            byte[] rawSignature;
            try {
                rawSignature = SignatureHelper.signHash(privateKey, hashBytes);
            } catch (Exception e) {
                throw new RuntimeException(
                        "Falha ao assinar hash id=" + tbsHash.getId() + ": " + e.getMessage(), e);
            }

            Signature sig = new Signature();
            sig.setRawSignature(Base64.getEncoder().encodeToString(rawSignature));
            sig.setDetached(tbsHash.getId());
            signatures.add(sig);
        }

        return new SignatureResponse(request.getCertificateAlias(), signatures);
    }

    /** Recupera a sessão autenticada injetada pelo {@link br.ufsc.labsec.pbad.selectionchallengepsc.interceptor.BearerTokenInterceptor}. */
    private Session getSessionFromRequest() {
        HttpServletRequest httpRequest =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        Session session = (Session) httpRequest.getAttribute("session");
        if (session == null) {
            throw new InvalidRequestException("Sessão autenticada não encontrada na requisição");
        }
        return session;
    }
}
