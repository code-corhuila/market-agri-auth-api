package co.edu.corhuila.marketagri.auth.application.port.in;

import java.time.Instant;

/** I-01: a caller of /internal/** gets its service token once per environment, when it is deployed (ADR-020 point 5). */
public interface IssueServiceToken {

    /** The token, or {@code InvalidClientCredentialsException} for an unknown client or a wrong secret. */
    ServiceToken issue(Command command);

    /** The client credentials; the HTTP adapter already refused a missing or empty field. */
    record Command(String clientId, String clientSecret) {

        @Override
        public String toString() {
            return "IssueServiceToken.Command[clientId=" + clientId + ", clientSecret=***]";
        }
    }

    record ServiceToken(String accessToken, Instant expiresAt) {

        @Override
        public String toString() {
            return "IssueServiceToken.ServiceToken[accessToken=***, expiresAt=" + expiresAt + "]";
        }
    }
}
