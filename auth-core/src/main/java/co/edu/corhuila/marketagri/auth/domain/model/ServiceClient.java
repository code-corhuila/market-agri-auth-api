package co.edu.corhuila.marketagri.auth.domain.model;

import java.util.regex.Pattern;

/**
 * A service that calls /internal/** (workflow, worker, chat; ADR-020 point 5). Its token says who it
 * is with {@code sub = service:<name>}; the name is lowercase so it cannot break the subject or the
 * {@code clientId:hash} pairs of the configuration.
 */
public record ServiceClient(String name) {

    private static final Pattern NAME = Pattern.compile("[a-z0-9]+(-[a-z0-9]+)*");
    private static final String SUBJECT_PREFIX = "service:";

    public ServiceClient {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("invalid service client name");
        }
    }

    public String subject() {
        return SUBJECT_PREFIX + name;
    }
}
