package br.ufsc.labsec.pbad.selectionchallengepsc.configuration;

import br.ufsc.labsec.pbad.selectionchallengepsc.model.PscUser;
import br.ufsc.labsec.pbad.selectionchallengepsc.repository.PscUserRepository;
import br.ufsc.labsec.pbad.selectionchallengepsc.util.CertificateGenerator;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Inicializa o banco de dados com dois usuários PSC, cada um com dois certificados:
 * um RSA 2048 e um ML-DSA 87 — ambos assinados pela CA AUTOMATIC_LOVE.
 *
 */
@Component
@Log4j2
@AllArgsConstructor
public class LoadDatabase {

    private static final String FIRST_NAME = "Pedro"; 
    private static final String ID_UFSC    = "22100919";
    private static final String CPF        = "13174020905";
    private static final int    SERVER_PORT = 8080;
    // =======================================================================

    private static final String CA_URL      = "https://pbad.labsec.ufsc.br/challenge/artifacts/rsa/AUTOMATIC_LOVE.p12";
    private static final String CA_PASSWORD = "1234";

    private PscUserRepository pscUserRepository;

    /**
     * Carrega a base de dados com os usuários iniciais da aplicação.
     * Verifica se a base já contém usuários para evitar duplicações em reinicializações.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void initDatabase() {
        log.info("Verificando inicialização do banco de dados...");

        if (pscUserRepository.count() > 0) {
            log.info("Banco de dados já inicializado. Pulando criação de usuários.");
            return;
        }

        try {
            Security.addProvider(new BouncyCastleProvider());

            log.info("Baixando certificado CA de {}", CA_URL);
            byte[] caBytes = downloadCa(CA_URL);

            KeyStore caKeyStore = CertificateGenerator.loadP12(caBytes, CA_PASSWORD);
            PrivateKey caPrivateKey  = CertificateGenerator.getPrivateKey(caKeyStore, CA_PASSWORD);
            X509Certificate caCert  = CertificateGenerator.getCertificate(caKeyStore);
            log.info("CA carregada: {}", caCert.getSubjectX500Principal().getName());

            PscUser user1 = createUser(FIRST_NAME + "-" + ID_UFSC, CPF,
                    "RSA", caPrivateKey, caCert);
            PscUser user2 = createUser(FIRST_NAME + "-" + ID_UFSC + "-PQC", incrementCpf(CPF),
                    "MLDSA", caPrivateKey, caCert);

            pscUserRepository.saveAll(List.of(user1, user2));
            log.info("Usuários inicializados: {} e {}", user1.getName(), user2.getName());

        } catch (Exception e) {
            log.error("Falha ao inicializar banco de dados: {}", e.getMessage(), e);
            throw new RuntimeException("Não foi possível inicializar o banco de dados", e);
        }
    }

    /**
     * Cria um {@link PscUser} com dois certificados (RSA 2048 e ML-DSA 87)
     * assinados pela CA fornecida.
     * @param name Nome do usuário
     * @param cpf CPF do usuário
     * @param defaultAlias Alias do certificado padrão ("RSA" ou "MLDSA")
     * @param caPrivateKey Chave privada da CA para assinar os certificados
     * @param caCert Certificado da CA para incluir na cadeia de certificação
     * @return Usuário criado com os certificados gerados
     * @throws Exception Se ocorrer algum erro durante a geração dos certificados
     */
    private PscUser createUser(String name, String cpf, String defaultAlias,
                               PrivateKey caPrivateKey, X509Certificate caCert) throws Exception {
        String subjectDN = "CN=" + name + ", OU=PBAD, O=UFSC, C=BR";
        String redirectUri = "http://localhost:" + SERVER_PORT + "/redirect/" + cpf;

        // Certificado RSA 2048
        KeyPair rsaKeyPair = CertificateGenerator.generateRsaKeyPair();
        X509Certificate rsaCert = CertificateGenerator.issueCertificate(subjectDN, rsaKeyPair.getPublic(), caPrivateKey, caCert);
        PscUser.UserCertificate rsaUserCert = new PscUser.UserCertificate(
                "Certificado RSA do usuário " + name,
                "RSA",
                rsaCert.getEncoded(),
                rsaKeyPair.getPrivate().getEncoded()
        );

        // Certificado ML-DSA 87
        KeyPair mldsaKeyPair = CertificateGenerator.generateMlDsaKeyPair();
        X509Certificate mldsaCert = CertificateGenerator.issueCertificate(subjectDN, mldsaKeyPair.getPublic(), caPrivateKey, caCert);
        PscUser.UserCertificate mldsaUserCert = new PscUser.UserCertificate(
                "Certificado MLDSA do usuário " + name,
                "MLDSA",
                mldsaCert.getEncoded(),
                mldsaKeyPair.getPrivate().getEncoded()
        );

        PscUser user = new PscUser();
        user.setName(name);
        user.setCpf(cpf);
        user.setDefaultCertificateAlias(defaultAlias);
        user.setRedirectUri(redirectUri);
        user.setCertificates(List.of(rsaUserCert, mldsaUserCert));

        return user;
    }

    /**
     * Baixa o arquivo .p12 da CA via HTTP.
     * @param url URL do arquivo .p12 da CA
     * @return Conteúdo do arquivo .p12 como array de bytes
     * @throws Exception Se ocorrer algum erro durante o download
     */
    private byte[] downloadCa(String url) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();
        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Falha ao baixar CA: HTTP " + response.statusCode());
        }
        return response.body();
    }

    /**
     * Incrementa o último dígito do CPF (para gerar CPF do usuário 2).
     * @param cpf CPF original como string de 11 dígitos
     * @return Novo CPF com o último dígito incrementado
     */
    private String incrementCpf(String cpf) {
        long value = Long.parseLong(cpf) + 1;
        return String.format("%011d", value);
    }
}
