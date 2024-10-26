package utils;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;

public class P7SVerifier {

    public static boolean verifyP7S(String p7sFilePath) throws IOException, CMSException, CertificateException, OperatorCreationException {
        // Read the .p7s file into a byte array
        FileInputStream fis = new FileInputStream(p7sFilePath);
        byte[] p7sData = fis.readAllBytes();
        fis.close();

        // Create a CMSSignedData object from the .p7s data
        CMSSignedData cmsSignedData = new CMSSignedData(p7sData);

        // Retrieve the signers and certificate store
        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();

        // Iterate through signers to verify integrity
        Collection<SignerInformation> signerCollection = signers.getSigners();
        for (SignerInformation signer : signerCollection) {
            // Verify the signature structure (without original data)
            Collection<X509CertificateHolder> certs = certStore.getMatches(signer.getSID());
            if (!certs.isEmpty()) {
                X509CertificateHolder certHolder = certs.iterator().next();
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder))) {
                    System.out.println("The .p7s file is structurally valid.");
                    return true;
                }
            }
        }
        System.out.println("The .p7s file is invalid or corrupted.");
        return false;
    }
}
