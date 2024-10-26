package org.example;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import utils.P7SVerifier;

import java.io.IOException;
import java.security.cert.CertificateException;

class Main{
    public static void main (String[] args) throws CertificateException, IOException, OperatorCreationException, CMSException {
        String file = "/cades_ad_rb_v2.3.p7s";
        P7SVerifier.verifyP7S(file);

    }
}