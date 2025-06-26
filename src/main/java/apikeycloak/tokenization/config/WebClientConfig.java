package apikeycloak.tokenization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {
    
    @Bean
    public WebClient webClient() {
        return WebClient.builder()
                // Opcional: base URL común (puedes poner la URL del admin o del token)
                .build();
    }
}
