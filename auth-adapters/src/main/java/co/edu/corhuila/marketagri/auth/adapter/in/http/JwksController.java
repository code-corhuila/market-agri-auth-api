package co.edu.corhuila.marketagri.auth.adapter.in.http;

import co.edu.corhuila.marketagri.auth.application.port.in.PublishSigningKey;
import co.edu.corhuila.marketagri.auth.domain.model.PublicSigningKey;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E-05 {@code GET /api/v1/auth/jwks} (HU-PLAT-002): anonymous, an RFC 7517 key set cached ten minutes. */
@RestController
@RequestMapping("/api/v1/auth")
public class JwksController {

    private static final String CACHE_TEN_MINUTES = "public, max-age=600";
    private static final String KEY_TYPE = "RSA";
    private static final String USE_SIGNATURE = "sig";
    private static final String ALGORITHM = "RS256";
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private final PublishSigningKey publishSigningKey;

    public JwksController(PublishSigningKey publishSigningKey) {
        this.publishSigningKey = publishSigningKey;
    }

    /** One JSON Web Key (RFC 7517 §4, RFC 7518 §6.3.1). */
    public record Jwk(String kty, String kid, String use, String alg, String n, String e) {
    }

    public record Jwks(List<Jwk> keys) {
    }

    @GetMapping("/jwks")
    public ResponseEntity<Jwks> jwks() {
        PublicSigningKey key = publishSigningKey.publicKey();
        Jwk jwk = new Jwk(KEY_TYPE, key.keyId(), USE_SIGNATURE, ALGORITHM,
                base64url(key.modulus()), base64url(key.exponent()));
        return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, CACHE_TEN_MINUTES).body(new Jwks(List.of(jwk)));
    }

    /** The unsigned big-endian bytes: {@code toByteArray} adds a 0x00 sign byte when the top bit is set. */
    private static String base64url(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return BASE64URL.encodeToString(bytes);
    }
}
