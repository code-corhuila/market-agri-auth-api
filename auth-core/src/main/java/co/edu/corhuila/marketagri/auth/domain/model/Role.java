package co.edu.corhuila.marketagri.auth.domain.model;

/** The single role of a user, fixed at registration (INV-001). {@code SERVICE} is a token role, never a user. */
public enum Role {
    PRODUCER,
    BUYER,
    ADMIN
}
