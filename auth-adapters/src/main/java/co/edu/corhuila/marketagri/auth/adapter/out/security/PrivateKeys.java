package co.edu.corhuila.marketagri.auth.adapter.out.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Reads the private key auth signs with from the file infra mounts read-only (keys/<env>/, written
 * by dev-keys.sh as a PKCS#8 PEM). It never comes from an env variable (ADR-020, infra README).
 */
public final class PrivateKeys {

    private static final String BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String END = "-----END PRIVATE KEY-----";

    private PrivateKeys() {
    }

    public static PrivateKey fromFile(Path file) {
        String pem;
        try {
            pem = Files.readString(file);
        } catch (IOException unreadable) {
            throw new IllegalStateException("Cannot read the JWT private key file " + file, unreadable);
        }
        if (!pem.contains(BEGIN)) {
            throw new IllegalStateException("The JWT private key file " + file + " is not a PKCS#8 PEM");
        }
        try {
            byte[] der = Base64.getMimeDecoder().decode(pem.replace(BEGIN, "").replace(END, ""));
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IllegalArgumentException | GeneralSecurityException invalid) {
            throw new IllegalStateException("The JWT private key file " + file + " is not an RSA key", invalid);
        }
    }
}
