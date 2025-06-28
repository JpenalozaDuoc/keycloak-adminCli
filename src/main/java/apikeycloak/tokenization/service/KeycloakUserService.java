package apikeycloak.tokenization.service;

import apikeycloak.tokenization.config.KeycloakProperties;
import apikeycloak.tokenization.dto.KeycloakUserResponse;
import apikeycloak.tokenization.dto.UsuarioRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.http.*;
import java.util.*;
import org.springframework.web.reactive.function.client.WebClient; // <-- Nuevo import
import reactor.core.publisher.Mono; // <-- Nuevo import (para el manejo reactivo)

@Slf4j
@Service
public class KeycloakUserService {

    private final WebClient webClient; // <-- Reemplaza RestTemplate por WebClient
    private final ObjectMapper objectMapper;
    private final KeycloakProperties keycloakProperties;

    public KeycloakUserService(
            WebClient webClient, // <-- Ahora inyectamos WebClient
            ObjectMapper objectMapper,
            KeycloakProperties keycloakProperties) {
        this.webClient = webClient; // <-- Asignamos WebClient
        this.objectMapper = objectMapper;
        this.keycloakProperties = keycloakProperties;
    }

    // -------------------------
    // 1. Crear usuario
    // -------------------------
    public void crearUsuario(UsuarioRequest usuarioRequest) {
        String tokenAdmin = obtenerTokenAdminApi();
        System.out.println("***********************************");
        System.out.println("TOKEN: "+tokenAdmin);
        System.out.println("***********************************");

        Map<String, Object> payload = new HashMap<>();
        payload.put("username", usuarioRequest.getUsername());
        payload.put("firstName", usuarioRequest.getFirstName());
        payload.put("lastName", usuarioRequest.getLastName());
        payload.put("email", usuarioRequest.getEmail());
        payload.put("emailVerified", usuarioRequest.getEmailVerified());
        payload.put("enabled", usuarioRequest.getEnabled());

        System.out.println("***********************************");
        System.out.println("Username: "+usuarioRequest.getUsername());
        System.out.println("firstName: "+usuarioRequest.getFirstName());
        System.out.println("lastName: "+usuarioRequest.getLastName());
        System.out.println("email: "+usuarioRequest.getEmail());
        System.out.println("***********************************");

        if (usuarioRequest.getAttributes() != null) {
            payload.put("attributes", usuarioRequest.getAttributes());
        }

        // Contraseña
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("type", "password");
        credentials.put("value", usuarioRequest.getPassword());
        credentials.put("temporary", false);
        payload.put("credentials", Collections.singletonList(credentials));

        String url = String.format("%s/admin/realms/%s/users", keycloakProperties.getServerUrl(), keycloakProperties.getRealm());
        System.out.println("***********************************");
        System.out.println("URL: "+url);
        System.out.println("***********************************");

        // --- CAMBIO A WEBCLIENT ---
        ResponseEntity<Void> response = webClient.post() // Inicia una solicitud POST
                .uri(url) // Define la URL
                .headers(h -> h.setBearerAuth(tokenAdmin)) // Configura encabezado de autorización
                .contentType(MediaType.APPLICATION_JSON) // Establece Content-Type
                .bodyValue(payload) // Envía el cuerpo de la solicitud (Map se serializa a JSON)
                .retrieve() // Inicia la recuperación de la respuesta
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al crear usuario en Keycloak: " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity() // Espera una respuesta sin cuerpo, pero con estado y headers
                .block(); // Bloquea hasta que la respuesta esté disponible

        // La verificación de errores se movió a .onStatus()
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

    // -------------------------
    // 2. Listar usuarios filtrando por username (opcional)
    // -------------------------
    public List<KeycloakUserResponse> listarUsuarios(String username) {
        String tokenAdmin = obtenerTokenAdminApi();
        String url = String.format("%s/admin/realms/%s/users", keycloakProperties.getServerUrl(), keycloakProperties.getRealm());

        if (username != null && !username.isEmpty()) {
            url += "?username=" + username;
        }

        // --- CAMBIO A WEBCLIENT ---
        List<KeycloakUserResponse> users = webClient.get() // Inicia una solicitud GET
                .uri(url) // Define la URL
                .headers(h -> h.setBearerAuth(tokenAdmin)) // Configura encabezado de autorización
                .retrieve() // Inicia la recuperación de la respuesta
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al listar usuarios: " + clientResponse.statusCode() + " - " + errorBody))))
                .bodyToMono(new ParameterizedTypeReference<List<KeycloakUserResponse>>() {}) // Espera un Mono de List<KeycloakUserResponse>
                .block(); // Bloquea para obtener el resultado

        return users != null ? users : Collections.emptyList(); // Devuelve una lista vacía si es nulo
    }

    // -------------------------
    // 3. Listar todos los usuarios (genérico, raw JSON)
    // -------------------------
    public List<KeycloakUserResponse> listarUsuariosGenerico() {
        return listarUsuarios(null); // Reusa listarUsuarios sin filtro
    }

    // -------------------------
    // 4. Asignar rol a usuario
    // -------------------------
    public void asignarRolAdmin(String userId, String rol) {
        String tokenAdmin = obtenerTokenAdminApi();

        // Primero obtener el rol específico desde Keycloak
        String urlRole = String.format("%s/admin/realms/%s/roles/%s", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), rol);

        // --- CAMBIO A WEBCLIENT para obtener rol ---
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

        // Asignar rol al usuario
        String urlAssign = String.format("%s/admin/realms/%s/users/%s/role-mappings/realm", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);

        // --- CAMBIO A WEBCLIENT para asignar rol ---
        webClient.post()
                .uri(urlAssign)
                .headers(h -> h.setBearerAuth(tokenAdmin))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Collections.singletonList(role)) // Envía una lista con el objeto rol
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error asignando rol a usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity() // No esperamos cuerpo de respuesta
                .block();
    }

    // -------------------------
    // 5. Eliminar roles públicos de usuario (ejemplo: quitar rol 'public')
    // -------------------------
    public void eliminarRolesUsuarioPublico(String userId) {
        String tokenAdmin = obtenerTokenAdminApi();

        String rolPublico = "public"; // Asumimos que el rol 'public' existe

        String urlRole = String.format("%s/admin/realms/%s/roles/%s", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), rolPublico);

        // --- CAMBIO A WEBCLIENT para obtener rol ---
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

        // Eliminar rol del usuario
        String urlDelete = String.format("%s/admin/realms/%s/users/%s/role-mappings/realm", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);

        // --- CAMBIO A WEBCLIENT para eliminar rol ---
        webClient.method(HttpMethod.DELETE) // Usa .method() para DELETE con body
                .uri(urlDelete)
                .headers(h -> h.setBearerAuth(tokenAdmin))
                .contentType(MediaType.APPLICATION_JSON) // DELETE con body suele requerir Content-Type
                .bodyValue(Collections.singletonList(role)) // Envía el cuerpo con el rol a eliminar
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error eliminando rol público de usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity()
                .block();
    }

    // -------------------------
    // 6. Actualizar usuario
    // -------------------------
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
        
        // --- CAMBIO A WEBCLIENT ---
        webClient.put() // Inicia una solicitud PUT
                .uri(url) // Define la URL
                .headers(h -> h.setBearerAuth(tokenAdmin)) // Configura encabezado de autorización
                .contentType(MediaType.APPLICATION_JSON) // Establece Content-Type
                .bodyValue(payload) // Envía el cuerpo de la solicitud
                .retrieve() // Inicia la recuperación de la respuesta
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error actualizando usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody))))
                .toBodilessEntity() // Espera una respuesta sin cuerpo
                .block(); // Bloquea hasta que la respuesta esté disponible
    }

    // -------------------------
    // 7. Obtener roles del cliente desde token JWT
    // -------------------------
    // Mantenemos este método, pero ya NO decodifica el token usando JJWT aquí.
    // Asumimos que el token ya ha sido validado por Spring Security.
    // Este método es para EXTRAER roles de un token VÁLIDO.
    public List<Map<String, Object>> obtenerRolesDelCliente(String token) {
        // En un entorno con Spring Security, no necesitarías decodificarlo manualmente con JJWT.
        // Spring Security ya habría procesado el token y podrías obtener los claims del SecurityContext.
        // Sin embargo, si este método es llamado con un token crudo por alguna razón,
        // y NO dependes de Spring Security para validarlo SIEMPRE antes de aquí,
        // necesitarías una lógica de decodificación.
        // Por ahora, y asumiendo que Spring Security lo hace, este método es un placeholder.
        // Para fines de demo, podemos simular la extracción o simplemente devolver una lista vacía.

        // Dado que hemos ELIMINADO la lógica de decodificación JJWT y la clave pública,
        // si este método realmente necesita los CLAIMS del token, necesitarías:
        // 1. Re-introducir JJWT (pero no la clave pública)
        // 2. O pasar un objeto `Jwt` de Spring Security aquí.
        // Por simplicidad, y asumiendo que este método puede ser refactorizado o no es crítico,
        // lo dejaremos devolviendo una lista vacía.
        // Si necesitas que este método REALMENTE lea los roles de un token JWT crudo,
        // dímelo y lo ajustamos para decodificar sin validar la firma.

        // Si la llamada es desde el controlador, y Spring Security ya validó el token,
        // la mejor forma sería inyectar Authentication y obtener los roles de ahí.
        // Por ahora, como no hay claims, devuelve vacío.
        log.warn("El método obtenerRolesDelCliente no decodifica el token. Usa Spring Security para obtener roles.");
        return Collections.emptyList();
    }


    // -------------------------
    // 8. Validar que token de usuario contenga rol admin
    // -------------------------
    // ELIMINADO: Esta lógica ahora es manejada por Spring Security con @PreAuthorize.
    // public boolean validarRolAdminDelUsuario(String tokenUsuario) { ... }


    // -------------------------
    // 9. Obtener token de admin para API Keycloak (client_credentials)
    // -------------------------
    public String obtenerTokenAdminApi() {
        String url = String.format("%s/realms/%s/protocol/openid-connect/token", keycloakProperties.getServerUrl(), keycloakProperties.getRealm());

        String body = "grant_type=client_credentials" +
                      "&client_id=" + keycloakProperties.getClientId() +
                      "&client_secret=" + keycloakProperties.getClientSecret();

        // --- CAMBIO A WEBCLIENT ---
        Map<String, Object> responseBody = webClient.post() // Inicia POST
                .uri(url) // Define la URL
                .contentType(MediaType.APPLICATION_FORM_URLENCODED) // Tipo de contenido para form-urlencoded
                .bodyValue(body) // Envía el cuerpo como String (form-urlencoded)
                .retrieve() // Inicia la recuperación
                .onStatus(HttpStatusCode::isError, clientResponse ->
                    clientResponse.bodyToMono(String.class)
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error al obtener token admin de Keycloak: " + clientResponse.statusCode() + " - " + errorBody))))
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {}) // Espera un Mono de Map
                .block(); // Bloquea para obtener el resultado

        if (responseBody == null || !responseBody.containsKey("access_token")) {
            throw new RuntimeException("Token admin inválido o no encontrado en la respuesta.");
        }

        return (String) responseBody.get("access_token");
    }

    // --- NUEVO MÉTODO: eliminarUsuario ---
    public void eliminarUsuario(String userId) {
        // 1. Obtener el token de administración de Keycloak
        // Asumo que KeycloakAdminClient.getAdminAccessToken() devuelve un Mono<String>
        String tokenAdmin = obtenerTokenAdminApi();
        
        if (tokenAdmin == null || tokenAdmin.isEmpty()) {
            throw new RuntimeException("No se pudo obtener el token de administración de Keycloak.");
        }

        // Construir la URL para eliminar el usuario
        // Ejemplo: https://vetcare360.duckdns.org/admin/realms/vetcare360/users/{userId}
        String url = String.format("%s/admin/realms/%s/users/%s", keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);

        System.out.println("DEBUG: Intentando eliminar usuario con ID: " + userId + " en URL: " + url);

        // 2. Realizar la llamada DELETE a la Admin API de Keycloak
        try {
            webClient.delete()
                    .uri(url)
                    .header("Authorization", "Bearer " + tokenAdmin)
                    .retrieve() // Inicia la recuperación de la respuesta
                    .onStatus(HttpStatusCode::is4xxClientError, response -> {
                        // Manejo de errores 4xx (ej. 404 Not Found si el usuario no existe, 403 Forbidden)
                        return response.bodyToMono(String.class).flatMap(body -> {
                            System.err.println("Error 4xx al eliminar usuario: " + body);
                            return Mono.error(new RuntimeException("Error del cliente al eliminar usuario: " + body));
                        });
                    })
                    .onStatus(HttpStatusCode::is5xxServerError, response -> {
                        // Manejo de errores 5xx (ej. problema interno del servidor Keycloak)
                        return response.bodyToMono(String.class).flatMap(body -> {
                            System.err.println("Error 5xx al eliminar usuario: " + body);
                            return Mono.error(new RuntimeException("Error del servidor Keycloak al eliminar usuario: " + body));
                        });
                    })
                    .toBodilessEntity() // Espera una respuesta sin cuerpo (ej. 204 No Content)
                    .block(); // Bloquea hasta que la operación se complete

            System.out.println("DEBUG: Usuario con ID: " + userId + " eliminado exitosamente.");
        } catch (Exception e) {
            System.err.println("ERROR: Fallo al eliminar usuario " + userId + ": " + e.getMessage());
            throw new RuntimeException("Fallo al eliminar usuario en Keycloak: " + e.getMessage(), e);
        }
    }
}
