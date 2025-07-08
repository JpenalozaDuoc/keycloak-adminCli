package apikeycloak.tokenization.service;

import apikeycloak.tokenization.client.KeycloakAdminClient;
import apikeycloak.tokenization.config.KeycloakProperties;
import apikeycloak.tokenization.dto.KeycloakUserResponse;
import apikeycloak.tokenization.dto.UsuarioRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.http.*;
import java.util.*;
import org.springframework.web.reactive.function.client.WebClient; 
import reactor.core.publisher.Mono; 

@Slf4j
@Service
public class KeycloakUserService {

    private final WebClient webClient; 
    private final ObjectMapper objectMapper;
    private final KeycloakProperties keycloakProperties;
    private final KeycloakAdminClient keycloakAdminClient; 

    public KeycloakUserService(
            WebClient webClient, 
            ObjectMapper objectMapper,
            KeycloakProperties keycloakProperties,
            KeycloakAdminClient keycloakAdminClient){ 
        this.webClient = webClient; 
        this.objectMapper = objectMapper;
        this.keycloakProperties = keycloakProperties;
        this.keycloakAdminClient = keycloakAdminClient; 
    }

    public void crearUsuario(UsuarioRequest usuarioRequest) {
        String tokenAdmin = obtenerTokenAdminApi();
        Map<String, Object> payload = new HashMap<>();
        payload.put("username", usuarioRequest.getUsername());
        payload.put("firstName", usuarioRequest.getFirstName());
        payload.put("lastName", usuarioRequest.getLastName());
        payload.put("email", usuarioRequest.getEmail());
        payload.put("emailVerified", usuarioRequest.getEmailVerified());
        payload.put("enabled", usuarioRequest.getEnabled());


        if (usuarioRequest.getAttributes() != null) {
            payload.put("attributes", usuarioRequest.getAttributes());
        }

        Map<String, Object> credentials = new HashMap<>();
        credentials.put("type", "password");
        credentials.put("value", usuarioRequest.getPassword());
        credentials.put("temporary", false);
        payload.put("credentials", Collections.singletonList(credentials));

        String url = String.format("%s/admin/realms/%s/users", keycloakProperties.getServerUrl(), keycloakProperties.getRealm());

        ResponseEntity<Void> response = webClient.post() 
                .uri(url) 
                .headers(h -> h.setBearerAuth(tokenAdmin)) 
                .contentType(MediaType.APPLICATION_JSON) 
                .bodyValue(payload) 
                .retrieve() 
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al crear usuario en Keycloak: " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity() 
                .block(); 

        String newUserId = null;
        if (response != null && response.getHeaders().containsKey(HttpHeaders.LOCATION)) {
            String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
            if (location != null) {
                newUserId = location.substring(location.lastIndexOf('/') + 1);
                log.info("Usuario creado exitosamente con ID: {}", newUserId);
            }
        }

        if (newUserId != null && usuarioRequest.getRol() != null && !usuarioRequest.getRol().isEmpty()) {
            try {
                asignarRolAdmin(newUserId, usuarioRequest.getRol());
                log.info("Rol '{}' asignado al usuario con ID: {}", usuarioRequest.getRol(), newUserId);
            } catch (RuntimeException e) {
                log.warn("Usuario creado pero NO se pudo asignar el rol '{}' al usuario con ID {}: {}",
                         usuarioRequest.getRol(), newUserId, e.getMessage());
            }
        }
    }

    public List<KeycloakUserResponse> listarUsuarios(String username) {
        String tokenAdmin = obtenerTokenAdminApi();
        String url = String.format("%s/admin/realms/%s/users", keycloakProperties.getServerUrl(), keycloakProperties.getRealm());

        if (username != null && !username.isEmpty()) {
            url += "?username=" + username;
        }
        List<KeycloakUserResponse> users = webClient.get() 
                .uri(url) 
                .headers(h -> h.setBearerAuth(tokenAdmin)) 
                .retrieve() 
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al listar usuarios: " + clientResponse.statusCode() + " - " + errorBody))))
                .bodyToMono(new ParameterizedTypeReference<List<KeycloakUserResponse>>() {}) 
                .block();

        return users != null ? users : Collections.emptyList(); 
    }

    public List<KeycloakUserResponse> listarUsuariosGenerico() {
        return listarUsuarios(null); 
    }

    public void asignarRolAdmin(String userId, String rol) {
        String tokenAdmin = obtenerTokenAdminApi();
        String urlRole = String.format("%s/admin/realms/%s/roles/%s", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), rol);
        Map<String, Object> role = webClient.get()
                .uri(urlRole)
                .headers(h -> h.setBearerAuth(tokenAdmin))
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al obtener rol '" + rol + "': " + clientResponse.statusCode() + " - " + errorBody))))
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

        if (role == null) {
            throw new RuntimeException("Rol no encontrado: " + rol);
        }
        String urlAssign = String.format("%s/admin/realms/%s/users/%s/role-mappings/realm", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);
        webClient.post()
                .uri(urlAssign)
                .headers(h -> h.setBearerAuth(tokenAdmin))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Collections.singletonList(role)) 
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error asignando rol a usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity() 
                .block();
    }

    public void eliminarRolesUsuarioPublico(String userId) {
        String tokenAdmin = obtenerTokenAdminApi();

        String rolPublico = "public"; 

        String urlRole = String.format("%s/admin/realms/%s/roles/%s", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), rolPublico);

        Map<String, Object> role = webClient.get()
                .uri(urlRole)
                .headers(h -> h.setBearerAuth(tokenAdmin))
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al obtener rol '" + rolPublico + "': " + clientResponse.statusCode() + " - " + errorBody))))
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

        if (role == null) {
            throw new RuntimeException("Rol público no encontrado: " + rolPublico);
        }

        String urlDelete = String.format("%s/admin/realms/%s/users/%s/role-mappings/realm", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);
        webClient.method(HttpMethod.DELETE)
                .uri(urlDelete)
                .headers(h -> h.setBearerAuth(tokenAdmin))
                .contentType(MediaType.APPLICATION_JSON) 
                .bodyValue(Collections.singletonList(role)) 
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error eliminando rol público de usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity()
                .block();
    }

    public void actualizarUsuario(String userId, UsuarioRequest usuarioRequest) {
        String tokenAdmin = obtenerTokenAdminApi();

        Map<String, Object> payload = new HashMap<>();
        payload.put("username", usuarioRequest.getUsername());
        payload.put("firstName", usuarioRequest.getFirstName());
        payload.put("lastName", usuarioRequest.getLastName());
        payload.put("email", usuarioRequest.getEmail());
        payload.put("emailVerified", usuarioRequest.getEmailVerified());
        payload.put("enabled", usuarioRequest.getEnabled());

        if (usuarioRequest.getAttributes() != null) {
            payload.put("attributes", usuarioRequest.getAttributes());
        }

        String url = String.format("%s/admin/realms/%s/users/%s", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);
        webClient.put() 
                .uri(url) 
                .headers(h -> h.setBearerAuth(tokenAdmin)) 
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(payload) 
                .retrieve() 
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error actualizando usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity() 
                .block(); 
    }

    public List<Map<String, Object>> obtenerRolesDelCliente(String token) {
        log.warn("El método obtenerRolesDelCliente no decodifica el token. Usa Spring Security para obtener roles.");
        return Collections.emptyList();
    }

    public String obtenerTokenAdminApi() {
        String url = String.format("%s/realms/%s/protocol/openid-connect/token", keycloakProperties.getServerUrl(), keycloakProperties.getRealm());

        String body = "grant_type=client_credentials" +
                      "&client_id=" + keycloakProperties.getClientId() +
                      "&client_secret=" + keycloakProperties.getClientSecret();

        Map<String, Object> responseBody = webClient.post() 
                .uri(url)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED) 
                .bodyValue(body) 
                .retrieve() 
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al obtener token admin de Keycloak: " + clientResponse.statusCode() + " - " + errorBody))))
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {}) // Espera un Mono de Map
                .block(); 

        if (responseBody == null || !responseBody.containsKey("access_token")) {
            throw new RuntimeException("Token admin inválido o no encontrado en la respuesta.");
        }

        return (String) responseBody.get("access_token");
    }

    public void eliminarUsuario(String userId) {
        String tokenAdmin = obtenerTokenAdminApi();
        
        if (tokenAdmin == null || tokenAdmin.isEmpty()) {
            throw new RuntimeException("No se pudo obtener el token de administración de Keycloak.");
        }
        String url = String.format("%s/admin/realms/%s/users/%s", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);
        try {
            webClient.delete()
                    .uri(url)
                    .header("Authorization", "Bearer " + tokenAdmin)
                    .retrieve() // Inicia la recuperación de la respuesta
                    .onStatus(HttpStatusCode::is4xxClientError, response -> {
                        return response.bodyToMono(String.class).flatMap(body -> {
                            System.err.println("Error 4xx al eliminar usuario: " + body);
                            return Mono.error(new RuntimeException("Error del cliente al eliminar usuario: " + body));
                        });
                    })
                    .onStatus(HttpStatusCode::is5xxServerError, response -> {
                        return response.bodyToMono(String.class).flatMap(body -> {
                            System.err.println("Error 5xx al eliminar usuario: " + body);
                            return Mono.error(new RuntimeException("Error del servidor Keycloak al eliminar usuario: " + body));
                        });
                    })
                    .toBodilessEntity() 
                    .block();

            System.out.println("DEBUG: Usuario con ID: " + userId + " eliminado exitosamente.");
        } catch (Exception e) {
            System.err.println("ERROR: Fallo al eliminar usuario " + userId + ": " + e.getMessage());
            throw new RuntimeException("Fallo al eliminar usuario en Keycloak: " + e.getMessage(), e);
        }
    }

    public Mono<KeycloakUserResponse> findUserById(String userId) {
        System.out.println("--- SERVICIO: Buscando usuario con ID: " + userId + " ---");
        return keycloakAdminClient.obtenerUsuarioPorId(userId)
                .map(userMap -> {
                    System.out.println("Usuario recibido en servicio: " + userMap);
                    Map<String, List<String>> attributes = new HashMap<>();
                    Object attrsObj = userMap.get("attributes");
                    if (attrsObj instanceof Map<?, ?>) {
                        Map<?, ?> rawAttrs = (Map<?, ?>) attrsObj;
                        for (Map.Entry<?, ?> entry : rawAttrs.entrySet()) {
                            if (entry.getKey() instanceof String && entry.getValue() instanceof List<?>) {
                                List<?> rawList = (List<?>) entry.getValue();
                                List<String> stringList = new ArrayList<>();
                                for (Object item : rawList) {
                                    if (item instanceof String) {
                                        stringList.add((String) item);
                                    }
                                }
                                attributes.put((String) entry.getKey(), stringList);
                            }
                        }
                    }

                    KeycloakUserResponse response = new KeycloakUserResponse();
                    response.setId((String) userMap.get("id"));
                    response.setUsername((String) userMap.get("username"));
                    response.setFirstName((String) userMap.get("firstName"));
                    response.setLastName((String) userMap.get("lastName"));
                    response.setEmail((String) userMap.get("email"));
                    response.setEmailVerified((Boolean) userMap.get("emailVerified"));
                    response.setEnabled((Boolean) userMap.get("enabled"));
                    response.setAttributes(attributes);
                    return response;
                })
                .switchIfEmpty(Mono.error(new NoSuchElementException("Usuario no encontrado con ID: " + userId)))
                .doOnError(e -> log.error("Error en findUserById para {}: {}", userId, e.getMessage()));
    }
}
