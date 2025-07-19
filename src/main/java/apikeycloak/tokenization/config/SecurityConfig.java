package apikeycloak.tokenization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.config.Customizer; 
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;

@Configuration
@EnableMethodSecurity

public class SecurityConfig{

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/keycloak/users/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            );

        return http.build();
    }

    @Bean
    @SuppressWarnings("unchecked") // <-- ¡AÑADE ESTA LÍNEA AQUÍ!
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        final String clientName = "vetcare-app"; 

        Converter<Jwt, Collection<GrantedAuthority>> customAuthoritiesConverter = jwt -> {
            System.out.println("--- INICIO PROCESAMIENTO JWT PARA ROLES DE CLIENTE ---");
            System.out.println("JWT Claims completos: " + jwt.getClaims());

            Map<String, Object> resourceAccess = (Map<String, Object>) jwt.getClaims().get("resource_access");
            System.out.println("resource_access claim: " + resourceAccess);

            if (resourceAccess == null || !resourceAccess.containsKey(clientName)) {
                System.out.println("resource_access no contiene roles para el cliente '" + clientName + "'.");
                System.out.println("--- FIN PROCESAMIENTO JWT ---");
                return List.of();
            }

            Map<String, Object> clientResource = (Map<String, Object>) resourceAccess.get(clientName);
            if (clientResource == null || !clientResource.containsKey("roles")) {
                System.out.println("El cliente '" + clientName + "' no tiene el claim 'roles' bajo resource_access.");
                System.out.println("--- FIN PROCESAMIENTO JWT ---");
                return List.of();
            }
            
            List<String> clientRoles = (List<String>) clientResource.get("roles");
            if (clientRoles == null || clientRoles.isEmpty()) {
                System.out.println("La lista de roles para el cliente '" + clientName + "' está vacía.");
                System.out.println("--- FIN PROCESAMIENTO JWT ---");
                return List.of();
            }

            System.out.println("Lista de roles extraídos para el cliente '" + clientName + "': " + clientRoles);

            List<GrantedAuthority> authorities = clientRoles.stream()
                .map(roleName -> {
                    String formattedRole = "ROLE_" + roleName.toUpperCase();
                    System.out.println("Mapeando rol '" + roleName + "' a '" + formattedRole + "'");
                    return new SimpleGrantedAuthority(formattedRole);
                })
                .collect(Collectors.toList());
            System.out.println("Autoridades Finales que se devolverán: " + authorities);
            System.out.println("--- FIN PROCESAMIENTO JWT ---");
            return authorities;
        };

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(customAuthoritiesConverter);
        return converter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(
            "http://localhost:4200",
            "https://funny-alfajores-7e9e6e.netlify.app"
            ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
