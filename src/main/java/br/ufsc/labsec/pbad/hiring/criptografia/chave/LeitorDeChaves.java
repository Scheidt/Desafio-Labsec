package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;


/**
 * Classe responsável por ler uma chave assimétrica do disco.
 *
 * @see KeyFactory
 * @see KeySpec
 */
public class LeitorDeChaves {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Lê a chave privada do local indicado.
     *
     * @param caminhoChave local do arquivo da chave privada.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave privada.
     */
    public static PrivateKey lerChavePrivadaDoDisco(String caminhoChave,
                                                    String algoritmo) {
        try (FileReader fileReader = new FileReader(caminhoChave);
             PEMParser pemParser = new PEMParser(fileReader)) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PEMKeyPair) {
                // Se o objeto for um par de chaves, extrai a chave privada
                PEMKeyPair pemKeyPair = (PEMKeyPair) object;
                KeyPair keyPair = converter.getKeyPair(pemKeyPair);
                return keyPair.getPrivate();
            } else if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                // Se o objeto for informações de chave privada
                org.bouncycastle.asn1.pkcs.PrivateKeyInfo privateKeyInfo = (org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object;
                return converter.getPrivateKey(privateKeyInfo);
            } else {
                throw new IOException("Tipo de chave privada não suportado no arquivo PEM.");
            }

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Lê a chave pública do local indicado.
     *
     * @param caminhoChave local do arquivo da chave pública.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave pública.
     */
    public static PublicKey lerChavePublicaDoDisco(String caminhoChave,
                                                   String algoritmo) {
        try (FileReader fileReader = new FileReader(caminhoChave);
             PEMParser pemParser = new PEMParser(fileReader)) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
                 org.bouncycastle.asn1.x509.SubjectPublicKeyInfo publicKeyInfo = (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object;
                 return converter.getPublicKey(publicKeyInfo);
            } else {
                throw new IOException("Tipo de chave pública não suportado no arquivo PEM.");
            }

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

}
