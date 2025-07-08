package apikeycloak.tokenization.client;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.stream.Collectors;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import apikeycloak.tokenization.config.KeycloakProperties;
import reactor.core.publisher.Mono;

@Component
public class KeycloakAdminClient {

    private final WebClient webClient; 
    private final KeycloakProperties keycloakProperties;
    private final String clientId;      // Para keycloak.client-id (vetcare-app-service)
    private final String clientSecret;  // Para keycloak.client-secret
    private final String tokenUri;      // Para keycloak.token-uri
    private final String adminUrl;      // Para keycloak.admin-url
    private final String clientName;    // Para keycloak.client-name (vetcare-app)
    private String adminAccessToken;
    private long tokenExpiryTime = 0;

    public KeycloakAdminClient(WebClient.Builder webClientBuilder, KeycloakProperties keycloakProperties) {
        this.webClient = webClientBuilder.build(); 
        this.keycloakProperties = keycloakProperties;
        this.clientId = keycloakProperties.getClientId();
        this.clientSecret = keycloakProperties.getClientSecret();
        this.tokenUri = keycloakProperties.getTokenUri();
        this.adminUrl = keycloakProperties.getAdminUrl();
        this.clientName = keycloakProperties.getClientName(); 

    }

    /**
     * Obtiene y cachea el token de acceso para las operaciones de administración de Keycloak
     * usando las credenciales del cliente de administración.
     * @return Mono<String> que emite el token de acceso.
     */
    public Mono<String> getAdminAccessToken() {
        if (adminAccessToken != null && System.currentTimeMillis() < tokenExpiryTime) {
            return Mono.just(adminAccessToken);
        }
        if (clientId == null) { System.err.println("ERROR DEBUG: clientId (para token de admin) es NULL!"); return Mono.error(new NullPointerException("clientId es NULL")); }
        if (clientSecret == null) { System.err.println("ERROR DEBUG: clientSecret (para token de admin) es NULL!"); return Mono.error(new NullPointerException("clientSecret es NULL")); }
        if (tokenUri == null) { System.err.println("ERROR DEBUG: tokenUri es NULL!"); return Mono.error(new NullPointerException("tokenUri es NULL")); }

        String body = "grant_type=client_credentials" +
                      "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                      "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

        return webClient.post()
                .uri(tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {}) 
                .doOnNext(responseBody -> { 
                    if (responseBody != null && responseBody.containsKey("access_token")) {
                        adminAccessToken = (String) responseBody.get("access_token");
                        Integer expiresIn = (Integer) responseBody.get("expires_in");
                        tokenExpiryTime = System.currentTimeMillis() + (expiresIn - 30) * 1000L; 
                        System.out.println("Token de administración de Keycloak obtenido/refrescado.");
                    } else {
                        throw new RuntimeException("No se pudo obtener token admin de Keycloak: Respuesta inválida o incompleta.");
                    }
                })
                .map(responseBody -> adminAccessToken)
                .onErrorResume(e -> {
                    System.err.println("Error al obtener el token de administración de Keycloak: " + e.getMessage());
                    return Mono.error(new RuntimeException("Error al obtener token admin de Keycloak", e));
                });
    }

    /**
     * Lista todos los usuarios en el realm de Keycloak.
     * @return Mono<String> que emite una cadena JSON con la lista de usuarios.
     */
    public Mono<String> listarUsuarios() {
        return getAdminAccessToken().flatMap(token ->
            webClient.get()
                .uri(adminUrl + "/users")
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(e -> {
                    System.err.println("Error al listar usuarios: " + e.getMessage());
                    return Mono.error(new RuntimeException("Error al listar usuarios", e));
                })
        );
    }


    /**
     * Crea un nuevo usuario en Keycloak.
     * @param usuarioPayload Un mapa que representa el payload JSON del usuario.
     * @return Mono<Void> que se completa cuando la operación es exitosa.
     */
    public Mono<Void> crearUsuario(Map<String, Object> usuarioPayload) {
        return getAdminAccessToken().flatMap(token ->
            webClient.post()
                .uri(adminUrl + "/users")
                .headers(headers -> {
                    headers.setBearerAuth(token);
                    headers.setContentType(MediaType.APPLICATION_JSON);
                })
                .bodyValue(usuarioPayload)
                .retrieve()
                .toBodilessEntity() 
                .then() 
                .onErrorResume(e -> {
                    System.err.println("Error al crear usuario: " + e.getMessage());
                    return Mono.error(new RuntimeException("Error creando usuario", e));
                })
        );
    }

    /**
     * Actualiza un usuario existente en Keycloak.
     * @param userId El ID interno del usuario.
     * @param usuarioPayload Un mapa que representa el payload JSON con los datos actualizados.
     * @return Mono<Void> que se completa cuando la operación es exitosa.
     */
    public Mono<Void> actualizarUsuario(String userId, Map<String, Object> usuarioPayload) {
        return getAdminAccessToken().flatMap(token ->
            webClient.put()
                .uri(adminUrl + "/users/" + userId)
                .headers(headers -> {
                    headers.setBearerAuth(token);
                    headers.setContentType(MediaType.APPLICATION_JSON);
                })
                .bodyValue(usuarioPayload)
                .retrieve()
                .toBodilessEntity()
                .then()
                .onErrorResume(e -> {
                    System.err.println("Error al actualizar usuario " + userId + ": " + e.getMessage());
                    return Mono.error(new RuntimeException("Error actualizando usuario", e));
                })
        );
    }

    /**
     * Elimina un usuario de Keycloak.
     * @param userId El ID interno del usuario a eliminar.
     * @return Mono<Void> que se completa cuando la operación es exitosa.
     */
    public Mono<Void> eliminarUsuario(String userId) {
        return getAdminAccessToken().flatMap(token ->
            webClient.delete()
                .uri(adminUrl + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .toBodilessEntity()
                .then()
                .onErrorResume(e -> {
                    System.err.println("Error al eliminar usuario " + userId + ": " + e.getMessage());
                    return Mono.error(new RuntimeException("Error eliminando usuario", e));
                })
        );
    }

    /**
     * Asigna un rol de Realm a un usuario en Keycloak.
     * @param userId El ID interno del usuario.
     * @param rolName El nombre del rol a asignar (ej. "admin", "veterinario").
     * @return Mono<Void> que se completa cuando la operación es exitosa.
     */
    
    public Mono<Void> asignarRolRealm(String userId, String rolName) {
        return getAdminAccessToken().flatMap(token -> {
            String roleUrl = adminUrl + "/roles/" + URLEncoder.encode(rolName, StandardCharsets.UTF_8);
            return webClient.get()
                .uri(roleUrl)
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(roleRepresentation -> {
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> rolesPayload = List.of((Map<String, Object>) roleRepresentation);

                    return webClient.post()
                        .uri(adminUrl + "/users/" + userId + "/role-mappings/realm")
                        .headers(headers -> {
                            headers.setBearerAuth(token);
                            headers.setContentType(MediaType.APPLICATION_JSON);
                        })
                        .bodyValue(rolesPayload)
                        .retrieve()
                        .toBodilessEntity()
                        .then()
                        .onErrorResume(e -> {
                            System.err.println("Error asignando rol de realm " + rolName + " a usuario " + userId + ": " + e.getMessage());
                            return Mono.error(new RuntimeException("Error asignando rol de realm", e));
                        });
                })
                .onErrorResume(e -> {
                    System.err.println("Error al obtener la representación del rol " + rolName + ": " + e.getMessage());
                    return Mono.error(new RuntimeException("Rol no encontrado o error al obtener rol: " + rolName, e));
                });
        });
    }

    /**
     * Asigna un rol de CLIENTE específico a un usuario en Keycloak.
     * @param userId El ID interno del usuario.
     * @param clientName El client_id del cliente (ej. "vetcare-app").
     * @param roleName El nombre del rol del cliente a asignar (ej. "admin", "veterinario").
     * @return Mono<Void> que se completa cuando la operación es exitosa.
     */
    
    public Mono<Void> asignarRolCliente(String userId, String clientName, String roleName) {
        return getAdminAccessToken().flatMap(token -> {
            String clientsSearchUrl = adminUrl + "/clients?clientId=" + URLEncoder.encode(clientName, StandardCharsets.UTF_8);
            return webClient.get()
                .uri(clientsSearchUrl)
                .headers(h -> h.setBearerAuth(token))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .flatMap(clients -> {
                    if (clients == null || clients.isEmpty()) {
                        return Mono.error(new RuntimeException("Cliente Keycloak con ID '" + clientName + "' no encontrado."));
                    }
                    String clientUuid = (String) clients.get(0).get("id");
                    String clientRoleUrl = adminUrl + "/clients/" + clientUuid + "/roles/" + URLEncoder.encode(roleName, StandardCharsets.UTF_8);
                    return webClient.get()
                        .uri(clientRoleUrl)
                        .headers(h -> h.setBearerAuth(token))
                        .retrieve()
                        .bodyToMono(Map.class)
                        .flatMap(roleRepresentation -> {
                            @SuppressWarnings("unchecked")
                            List<Map<String, Object>> rolesPayload = List.of((Map<String, Object>) roleRepresentation);
                            String assignRoleUrl = adminUrl + "/users/" + userId + "/role-mappings/clients/" + clientUuid;
                            return webClient.post()
                                .uri(assignRoleUrl)
                                .headers(headers -> {
                                    headers.setBearerAuth(token);
                                    headers.setContentType(MediaType.APPLICATION_JSON);
                                })
                                .bodyValue(rolesPayload)
                                .retrieve()
                                .toBodilessEntity()
                                .then()
                                .onErrorResume(e -> {
                                    System.err.println("Error asignando rol de cliente " + roleName + " a usuario " + userId + ": " + e.getMessage());
                                    return Mono.error(new RuntimeException("Error asignando rol de cliente", e));
                                });
                        })
                        .onErrorResume(e -> {
                            System.err.println("Error al obtener la representación del rol de cliente " + roleName + ": " + e.getMessage());
                            return Mono.error(new RuntimeException("Rol de cliente no encontrado o error al obtener rol: " + roleName, e));
                        });
                })
                .onErrorResume(e -> {
                    System.err.println("Error al buscar cliente " + clientName + " para asignar rol: " + e.getMessage());
                    return Mono.error(new RuntimeException("Error al buscar cliente para asignar rol", e));
                });
        });
    }

    /**
     * Obtiene todos los roles definidos para el cliente específico (ej. "vetcare-app") en Keycloak.
     * @return Mono<List<String>> que emite una lista de nombres de roles de cliente.*/

    public Mono<List<String>> getAllRolesForTargetClient() {
        return getAdminAccessToken().flatMap(token -> {
            String clientsSearchUrl = adminUrl + "/clients?clientId=" + URLEncoder.encode(clientName, StandardCharsets.UTF_8);
            
            return webClient.get()
                    .uri(clientsSearchUrl)
                    .headers(h -> h.setBearerAuth(token))
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                    .flatMap((List<Map<String, Object>> clients) -> {
                        if (clients == null || clients.isEmpty()) {
                            System.err.println("Cliente Keycloak con ID '" + clientName + "' no encontrado.");
                            return Mono.just(Collections.<String>emptyList());
                        }

                        String clientUuid = (String) clients.get(0).get("id");
                        String clientRolesUrl = adminUrl + "/clients/" + clientUuid + "/roles";

                        return webClient.get()
                                .uri(clientRolesUrl)
                                .headers(h -> h.setBearerAuth(token))
                                .retrieve()
                                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                                .map((List<Map<String, Object>> rolesResponse) -> {
                                    if (rolesResponse == null) {
                                        return Collections.<String>emptyList();
                                    }
                                    return rolesResponse.stream()
                                            .map(role -> (String) role.get("name"))
                                            .collect(Collectors.toList());
                                })
                                .onErrorResume(e -> {
                                    System.err.println("Error al obtener los roles del cliente " + clientName + ": " + e.getMessage());
                                    return Mono.error(new RuntimeException("Error al obtener los roles del cliente", e));
                                });
                    })
                    .onErrorResume(e -> {
                        System.err.println("Error al buscar el cliente '" + clientName + "' para obtener roles: " + e.getMessage());
                        return Mono.error(new RuntimeException("Error al buscar el cliente para roles", e));
                    });
        });
    }

    /**
     * Obtiene una lista de usuarios que tienen asignado directamente un rol de REINO.
     * Nota: Esto no incluye usuarios que obtienen el rol a través de grupos o roles compuestos.
     * @param realmRoleName El nombre del rol de reino (ej. "realm_admin").
     * @return Mono<List<Map<String, Object>>> que emite una lista de objetos de usuario (Map).
     */
    public Mono<List<Map<String, Object>>> getUsersByRealmRole(String realmRoleName) {
        return getAdminAccessToken().flatMap(token ->
            webClient.get()
                .uri(adminUrl + "/roles/" + URLEncoder.encode(realmRoleName, StandardCharsets.UTF_8) + "/users")
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .onErrorResume(e -> {
                    System.err.println("Error al obtener usuarios con rol de reino '" + realmRoleName + "': " + e.getMessage());
                    return Mono.error(new RuntimeException("Error al obtener usuarios por rol de reino", e));
                })
        );
    }

    /**
     * Obtiene una lista de usuarios que tienen asignado directamente un rol de CLIENTE
     * para el cliente de la aplicación principal (definido por 'clientName').
     * Nota: Esto no incluye usuarios que obtienen el rol a través de grupos o roles compuestos.
     * @param clientRoleName El nombre del rol de cliente (ej. "admin", "veterinario").
     * @return Mono<List<Map<String, Object>>> que emite una lista de objetos de usuario (Map).
     */
    public Mono<List<Map<String, Object>>> getUsersByClientRole(String clientRoleName) {
        return getAdminAccessToken().flatMap(token ->
            webClient.get()
                .uri(adminUrl + "/clients?clientId=" + URLEncoder.encode(this.clientName, StandardCharsets.UTF_8))
                .headers(h -> h.setBearerAuth(token))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .flatMap(clients -> {
                    if (clients == null || clients.isEmpty()) {
                        System.err.println("Cliente Keycloak con ID '" + this.clientName + "' no encontrado para buscar roles.");
                        return Mono.<List<Map<String, Object>>>just(Collections.emptyList()); 
                    }
                    String clientUuid = (String) clients.get(0).get("id");
                    String usersByClientRoleUrl = adminUrl + "/clients/" + clientUuid + "/roles/" + URLEncoder.encode(clientRoleName, StandardCharsets.UTF_8) + "/users";
                    return webClient.get()
                        .uri(usersByClientRoleUrl)
                        .headers(h -> h.setBearerAuth(token))
                        .retrieve()
                        .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                        .onErrorResume(e -> {
                            System.err.println("Error al obtener usuarios con rol de cliente '" + clientRoleName + "' para cliente '" + this.clientName + "': " + e.getMessage());
                            return Mono.error(new RuntimeException("Error al obtener usuarios por rol de cliente", e));
                        });
                })
                .onErrorResume(e -> {
                    System.err.println("Error al buscar cliente o rol para obtener usuarios por rol de cliente: " + e.getMessage());
                    return Mono.error(new RuntimeException("Error en proceso de getUsersByClientRole", e));
                })
        );
    }

    /**
     * Obtiene un usuario específico por su ID.
     * @param userId El ID interno del usuario en Keycloak.
     * @return Mono<Map<String, Object>> que emite un mapa con los detalles del usuario.
     * Emite Mono.empty() si el usuario no es encontrado (404).
     */
    public Mono<Map<String, Object>> obtenerUsuarioPorId(String userId) {
        System.out.println("--- CLIENT: Buscando usuario con ID: " + userId + " en " + adminUrl + "/users/" + userId + " ---");
        return getAdminAccessToken().flatMap(token ->
            webClient.get()
                .uri(adminUrl + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .onStatus(status -> status == HttpStatus.NOT_FOUND, clientResponse -> {
                    System.out.println("Usuario con ID '" + userId + "' no encontrado (HTTP 404).");
                    return Mono.empty(); 
                })
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> {
                                      System.err.println("Error al obtener usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody);
                                      return Mono.error(new RuntimeException("Error al obtener usuario: " + userId + " - " + errorBody));
                                  })
                )
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .doOnSuccess(userMap -> {
                    if (userMap != null) {
                        System.out.println("Respuesta de Keycloak para usuario " + userId + ": " + userMap);
                    }
                })
                .doOnError(e -> System.err.println("Error reactivo en obtenerUsuarioPorId: " + e.getMessage()))
        );
    }


}
