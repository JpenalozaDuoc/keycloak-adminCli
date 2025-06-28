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
//import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.config.Customizer; // Importa Customizer
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
//import org.keycloak.adapters.springsecurity.KeycloakConfiguration;

@Configuration
@EnableMethodSecurity
//@KeycloakConfiguration
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
        configuration.setAllowedOrigins(List.of("http://localhost:4200"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Desactiva CSRF para APIs REST (stateless)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // API RESTful son stateless
            .cors(Customizer.withDefaults()) // Integra tu bean CorsConfigurationSource
            .authorizeHttpRequests(auth -> auth
                // Todos los endpoints bajo /api/** deben ser AUTENTICADOS.
                // La autorización por rol (@PreAuthorize) se manejará a nivel de método.
                .requestMatchers("/api/keycloak/users/**").authenticated() // Protege tus endpoints de usuarios Keycloak
                .anyRequest().authenticated() // Asegura que cualquier otra petición también esté autenticada
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults()) // Configura para ser un Resource Server que valida JWTs
            );

        return http.build();
    }

    // --- NUEVO BEAN PARA EL MAPEADOR DE ROLES ---
     @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        // Define el nombre de tu cliente Keycloak aquí
        final String clientName = "vetcare-app"; // <-- ¡IMPORTANTE! Reemplaza con tu client_id

        Converter<Jwt, Collection<GrantedAuthority>> customAuthoritiesConverter = jwt -> {
            Object resourceAccessObj = jwt.getClaims().get("resource_access");
            if (!(resourceAccessObj instanceof Map<?, ?> resourceAccessRaw)) {
                return List.of(); // No hay roles para este cliente
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> resourceAccess = (Map<String, Object>) resourceAccessRaw;

            // Verifica si 'resource_access' y tu cliente existen
            if (resourceAccess.isEmpty() || !resourceAccess.containsKey(clientName)) {
                return List.of(); // No hay roles para este cliente
            }

            Object clientResourceObj = resourceAccess.get(clientName);
            if (!(clientResourceObj instanceof Map<?, ?> clientResourceRaw)) {
                return List.of(); // No hay roles asignados dentro de este cliente
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> clientResource = (Map<String, Object>) clientResourceRaw;

            Object rolesObj = clientResource.get("roles");
            if (!(rolesObj instanceof List<?> rolesRaw)) {
                return List.of(); // No hay roles asignados dentro de este cliente
            }
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) rolesRaw;

            if (roles == null || roles.isEmpty()) {
                return List.of(); // No hay roles asignados dentro de este cliente
            }

            // Convierte los roles a GrantedAuthority, añadiendo "ROLE_" y mayúsculas
            return roles.stream()
                    .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName.toUpperCase()))
                    .collect(Collectors.toList());
        };

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(customAuthoritiesConverter);
        return converter;
    }
    // --- FIN NUEVO BEAN ---

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Orígenes permitidos - Asegúrate que sean EXACTOS
        configuration.setAllowedOrigins(List.of("http://localhost:4200"));
        // Métodos permitidos - Incluye OPTIONS para preflight requests
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // Encabezados permitidos - Importante incluir Authorization para JWTs de Keycloak
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
        // Permite credenciales (necesario si envías Authorization headers o cookies)
        configuration.setAllowCredentials(true);
        // Tiempo que los resultados de preflight pueden ser cacheaddos
        configuration.setMaxAge(3600L); // 1 hora

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Aplica esta configuración CORS a todas las rutas.
        // Si solo quieres /api/**, cámbialo a "/api/**"
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
    */
    /*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Deshabilitar CSRF si usas API REST
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(withDefaults()) // Configuración JWT por defecto
            );

        return http.build();
    }
    */
    /*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Desactivar CSRF para APIs REST
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // APIs REST usan STATELESS
            .cors(Customizer.withDefaults()) // <--- ¡AQUÍ LA CLAVE! Conecta tu CorsConfigurationSource bean
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").permitAll() // Por ahora, permitimos todo en /api/** para CORS
                                                      // Después puedes refinar con hasRole, authenticated, etc.
                .anyRequest().authenticated() // El resto requiere autenticación
            );

        // Si tu configuración de Keycloak es más específica y necesitas filtros custom:
        // KeycloakConfiguration suele añadir filtros automáticamente, pero si necesitas
        // un control más fino, aquí se añadirían los filtros de Keycloak,
        // por ejemplo, para proteger ciertos endpoints con Keycloak.
        // Asegúrate de que los filtros de Keycloak estén en el orden correcto
        // y que no anulen tu configuración de CORS si no tienen su propia.

        return http.build();
    }
    */

}
