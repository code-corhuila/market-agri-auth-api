package co.edu.corhuila.marketagri.auth.adapter.in.http;

import co.edu.corhuila.marketagri.auth.application.port.in.IssueServiceToken;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidClientCredentialsException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * I-01 {@code POST /internal/v1/auth/service-token} (HU-PLAT-002): client credentials in the body,
 * never routed by the gateway; called once per caller and environment, when the caller is deployed.
 */
@PublicEndpoint
@RestController
@RequestMapping("/internal/v1/auth")
public class ServiceTokenController {

    private static final Logger LOG = LoggerFactory.getLogger(ServiceTokenController.class);

    private final IssueServiceToken issueServiceToken;

    public ServiceTokenController(IssueServiceToken issueServiceToken) {
        this.issueServiceToken = issueServiceToken;
    }

    /** {@code ServiceTokenRequest}: a missing or empty field is 400, named in {@code details}. */
    public record ServiceTokenRequest(@NotBlank(message = "Es obligatorio.") String clientId,
                                      @NotBlank(message = "Es obligatorio.") String clientSecret) {

        @Override
        public String toString() {
            return "ServiceTokenRequest[clientId=" + clientId + ", clientSecret=***]";
        }
    }

    /** {@code ServiceTokenResponse}. */
    public record ServiceTokenResponse(String accessToken, Instant expiresAt) {
    }

    @PostMapping("/service-token")
    public ServiceTokenResponse issue(@Valid @RequestBody ServiceTokenRequest body) {
        try {
            IssueServiceToken.ServiceToken token =
                    issueServiceToken.issue(new IssueServiceToken.Command(body.clientId(), body.clientSecret()));
            // ADR-020: the expiry date of every SERVICE_TOKEN is noted; the token itself never is.
            LOG.atInfo().addKeyValue("clientId", body.clientId()).addKeyValue("expiresAt", token.expiresAt())
                    .log("Service token issued");
            return new ServiceTokenResponse(token.accessToken(), token.expiresAt());
        } catch (InvalidClientCredentialsException refused) {
            LOG.atWarn().addKeyValue("clientId", body.clientId()).log("Service token refused: invalid client credentials");
            throw refused;
        }
    }
}
