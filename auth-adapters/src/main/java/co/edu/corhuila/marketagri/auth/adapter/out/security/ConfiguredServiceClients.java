package co.edu.corhuila.marketagri.auth.adapter.out.security;

import co.edu.corhuila.marketagri.auth.application.port.out.ServiceClients;
import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The callers of I-01 from AUTH_SERVICE_CLIENTS (authentication.md §7): {@code clientId:hash} pairs
 * separated by commas, the hash being the SHA-256 of the secret in lowercase hex
 * ({@code printf %s "$SECRET" | sha256sum}). SHA-256 and not bcrypt, as for the refresh tokens: the
 * secret is random and long. A malformed entry stops the service, without printing it.
 */
public final class ConfiguredServiceClients implements ServiceClients {

    private static final String VARIABLE = "AUTH_SERVICE_CLIENTS";
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");

    private final Map<String, byte[]> secretHashes = new HashMap<>();

    public ConfiguredServiceClients(String configuration) {
        if (configuration == null || configuration.isBlank()) {
            return;
        }
        int position = 0;
        for (String entry : configuration.split(",")) {
            position++;
            String[] pair = entry.strip().split(":", -1);
            if (pair.length != 2 || !SHA256_HEX.matcher(pair[1]).matches() || !validName(pair[0])) {
                throw new IllegalStateException(VARIABLE + ": entry " + position + " is not clientId:sha256-hex");
            }
            if (secretHashes.put(pair[0], HexFormat.of().parseHex(pair[1])) != null) {
                throw new IllegalStateException(VARIABLE + ": entry " + position + " repeats a clientId");
            }
        }
    }

    @Override
    public Optional<ServiceClient> authenticate(String clientId, String clientSecret) {
        byte[] expected = secretHashes.get(clientId);
        byte[] given = sha256(clientSecret);
        // Constant-time comparison: the answer time does not reveal how much of the secret matched.
        return expected != null && MessageDigest.isEqual(expected, given)
                ? Optional.of(new ServiceClient(clientId))
                : Optional.empty();
    }

    private static boolean validName(String name) {
        try {
            new ServiceClient(name);
            return true;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static byte[] sha256(String secret) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("every JVM has SHA-256", impossible);
        }
    }
}
