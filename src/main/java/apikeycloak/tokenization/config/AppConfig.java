package apikeycloak.tokenization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {

    @Bean // Este método crea y configura un bean de RestTemplate
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
