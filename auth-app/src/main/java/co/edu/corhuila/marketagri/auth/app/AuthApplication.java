package co.edu.corhuila.marketagri.auth.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Raíz de composición. Escanea la app y los adaptadores; el núcleo no lleva anotaciones
 * de Spring, así que sus tipos se instancian explícitamente en {@link AuthConfiguration}.
 */
@SpringBootApplication(scanBasePackages = {"co.edu.corhuila.marketagri.auth.app", "co.edu.corhuila.marketagri.auth.adapter"})
public class AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
