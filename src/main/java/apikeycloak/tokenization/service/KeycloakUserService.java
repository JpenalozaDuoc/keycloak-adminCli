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
//import java.util.stream.Collectors;
//import java.util.stream.Collectors;

import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Flux;
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
                // *** CAMBIO CLAVE AQUÍ: Usamos el nuevo método para asignar rol de cliente ***
                // Asumimos que `usuarioRequest.getRol()` contendrá un rol de cliente (ej. "VETERINARIO", "ASISTENTE")
                // Y `keycloakProperties.getClientName()` será el `client_id` de tu aplicación (ej. "vetcare-app")
                //asignarRolAdmin(newUserId, usuarioRequest.getRol());
                asignarRolClienteAUsuario(newUserId, usuarioRequest.getRol());
                log.info("Rol '{}' asignado al usuario con ID: {}", usuarioRequest.getRol(), newUserId);
            } catch (RuntimeException e) {
                log.warn("Usuario creado pero NO se pudo asignar el rol '{}' al usuario con ID {}: {}",
                         usuarioRequest.getRol(), newUserId, e.getMessage());
            }
        }
    }
    /**
    * Lista todos los usuarios de Keycloak, obteniendo sus detalles y el nombre de su rol principal
    * para el cliente de la aplicación.
    * @return Mono<List<KeycloakUserResponse>> que emite una lista de usuarios con su nombre de rol.
    */
    public Mono<List<KeycloakUserResponse>> listarUsuariosConRolSimple() {
        return keycloakAdminClient.listarUsuariosMap() // Obtiene la lista de usuarios como Map<String, Object>
            .flatMapMany(Flux::fromIterable) // Convierte la lista en un Flux de usuarios individuales
            .flatMap(userMap -> {
                String userId = (String) userMap.get("id");
                // Mapear los campos básicos del usuario primero
                KeycloakUserResponse userResponse = new KeycloakUserResponse();
                userResponse.setId(userId);
                userResponse.setUsername((String) userMap.get("username"));
                userResponse.setFirstName((String) userMap.get("firstName"));
                userResponse.setLastName((String) userMap.get("lastName"));
                userResponse.setEmail((String) userMap.get("email"));
                userResponse.setEnabled((Boolean) userMap.get("enabled"));
                userResponse.setEmailVerified((Boolean) userMap.get("emailVerified"));
                @SuppressWarnings("unchecked")
                Map<String, List<String>> attributes = (Map<String, List<String>>) userMap.getOrDefault("attributes", Collections.emptyMap());
                userResponse.setAttributes(attributes);

                // Luego, obtener los roles de cliente para este usuario
                return keycloakAdminClient.obtenerRolesClienteDeUsuario(userId, keycloakProperties.getClientName())//private String clientName;  //keycloak.client-name=vetcare-app
                    .map(rawRoles -> { // Cambiamos el nombre de la variable a 'rawRoles' para claridad
                    // Hacemos el cast explícito aquí para asegurar que el compilador lo entienda
                    System.out.println("**************************************************");
                    System.out.println(userId);
                    System.out.println(rawRoles);
                    System.out.println("**************************************************");
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> roles = (List<Map<String, Object>>) rawRoles;
                        System.out.println("**************************************************");
                        System.out.println("Pase por ACA: "+roles);
                        System.out.println("**************************************************");
                        String rolAsignado = "N/A";
                        
                        if (roles != null && !roles.isEmpty()) {
                            Map<String, Object> primerRol = roles.get(0);
                            System.out.println("Este debe ser el primer rol: " + primerRol);

                            if (primerRol != null && primerRol.containsKey("name")) {
                                Object roleNameObj = primerRol.get("name");
                                if (roleNameObj instanceof String) {
                                    rolAsignado = (String) roleNameObj;
                                } else {
                                    System.err.println("DEBUG: El 'name' del rol para usuario " + userId + " no es un String o es nulo: " + roleNameObj);
                                    rolAsignado = "Rol Desconocido";
                                }
                            } else {
                                System.err.println("DEBUG: El primer rol para usuario " + userId + " no contiene la clave 'name'.");
                                rolAsignado = "Sin Nombre de Rol";
                            }
                        } else {
                            System.out.println("DEBUG: No se encontraron roles para el usuario " + userId + " o la lista está vacía.");
                        }

                        /*
                        if (roles != null && !!roles.isEmpty()) {

                            Map<String, Object> primerRol = roles.get(0);
                            System.out.println("**************************************************");
                            System.out.println("Este debe ser el primer rol: "+primerRol);
                            System.out.println(rawRoles);
                            System.out.println("**************************************************");
                        // Verificar si el rol existe y tiene la clave "name"
                            if (primerRol != null && primerRol.containsKey("name")) {
                                Object roleNameObj = primerRol.get("name");
                                if (roleNameObj instanceof String) {
                                    rolAsignado = (String) roleNameObj;
                                    System.out.println("**************************************************");
                                    System.out.println(roleNameObj);
                                    System.out.println("**************************************************");
                                } else {
                                    // Si "name" no es String o es nulo, manejar como "Desconocido"
                                    System.err.println("DEBUG: El 'name' del rol para usuario " + userId + " no es un String o es nulo: " + roleNameObj);
                                    rolAsignado = "Rol Desconocido";
                                }
                            } else {
                                System.err.println("DEBUG: El primer rol para usuario " + userId + " no contiene la clave 'name'.");
                                rolAsignado = "Sin Nombre de Rol";
                            }
                        } else {
                            System.out.println("DEBUG: No se encontraron roles para el usuario " + userId + " o la lista está vacía.");
                            // rolAsignado ya es "N/A" por defecto
                        }
                        */
                        userResponse.setRol(rolAsignado);
                        return userResponse;
                    })
                    .defaultIfEmpty(userResponse) // Si no hay roles, aún así devuelve el userResponse (con rol "N/A")
                    .onErrorResume(e -> {
                        System.err.println("Error al obtener roles para el usuario " + userId + ": " + e.getMessage());
                        userResponse.setRol("Error al cargar rol"); // Asigna un mensaje de error si falla
                        return Mono.just(userResponse); // Devuelve el usuario con el error de rol
                    });
            })
            .collectList() // Recolecta todos los Monos resultantes en una sola lista
            .onErrorResume(e -> {
                System.err.println("Error en el servicio al listar usuarios y sus roles simples: " + e.getMessage());
                return Mono.error(new RuntimeException("No se pudieron listar usuarios con roles", e));
            });
    }
    /*
    public List<Map<String, Object>> listarUsuarios() {
        // Usamos método bloqueante porque es servicio síncrono
        return keycloakAdminClient.listarUsuariosMap().block();
    }
    */

    /*
    public List<Map<String, Object>> listarUsuariosConRoles(String clientName) {
        return keycloakAdminClient.listarUsuariosConRolesDeCliente(clientName).block();
    }
    */

    /*
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
    */

    /*
    public List<KeycloakUserResponse> listarUsuariosConRoles(String usernameFiltro) {
    List<KeycloakUserResponse> usuarios = listarUsuarios(usernameFiltro); // Ya tienes este método
        String clientId = keycloakProperties.getClientName();

        for (KeycloakUserResponse usuario : usuarios) {
            try {
                List<Map<String, Object>> rolesRaw = obtenerRolesClienteDeUsuario(usuario.getId(), clientId).block();

                if (rolesRaw != null && !rolesRaw.isEmpty()) {
                    // Opcional: puedes concatenar roles si hay más de uno
                    String rolesConcatenados = rolesRaw.stream()
                            .map(r -> (String) r.get("name"))
                            .collect(Collectors.joining(", "));

                    usuario.setRol(rolesConcatenados); // Seteamos al DTO
                } else {
                    usuario.setRol("SIN_ROL");
                }

            } catch (Exception e) {
                System.err.println("Error al obtener roles del usuario " + usuario.getUsername() + ": " + e.getMessage());
                usuario.setRol("ERROR");
            }
        }

        return usuarios;
    }
    */

    /*
    public List<KeycloakUserResponse> listarUsuariosGenerico() {
        return listarUsuarios(null); 
    }
    */

    // *** NUEVO MÉTODO PARA ASIGNAR ROL DE CLIENTE ***
    public void asignarRolClienteAUsuario(String userId, String rolCliente) {
        log.info("Intentando asignar rol de cliente '{}' al usuario con ID '{}' para el cliente '{}'",
                rolCliente, userId, keycloakProperties.getClientName());
        try {
            // Llama al método del KeycloakAdminClient que ya sabe cómo manejar roles de cliente
            keycloakAdminClient.asignarRolCliente(userId, keycloakProperties.getClientName(), rolCliente).block();
            log.info("Rol de cliente '{}' asignado exitosamente al usuario con ID '{}'.", rolCliente, userId);
        } catch (Exception e) {
            log.error("Error al asignar el rol de cliente '{}' al usuario con ID '{}': {}", rolCliente, userId, e.getMessage());
            throw new RuntimeException("Error al asignar rol de cliente: " + e.getMessage(), e);
        }
    }

    public void asignarRolAdminRealm(String userId, String rol) {
        log.warn("Usando el método de asignación de rol de REINO. Asegúrate de que el rol '{}' es un rol de reino.", rol);
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
                                  .flatMap(errorBody -> Mono.error(new RuntimeException("Error asignando rol de REALM a usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody))))
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

    public void eliminarRolClienteAUsuario(String userId, String rolCliente) {
        log.info("Intentando eliminar rol de cliente '{}' del usuario con ID '{}' para el cliente '{}'",
                rolCliente, userId, keycloakProperties.getClientName());
        try {
            keycloakAdminClient.eliminarRolCliente(userId, keycloakProperties.getClientName(), rolCliente).block();
            log.info("Rol de cliente '{}' eliminado exitosamente del usuario con ID '{}'.", rolCliente, userId);
        } catch (Exception e) {
            log.error("Error al eliminar el rol de cliente '{}' del usuario con ID '{}': {}", rolCliente, userId, e.getMessage());
            throw new RuntimeException("Error al eliminar rol de cliente: " + e.getMessage(), e);
        }
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

        if (usuarioRequest.getPassword() != null && !usuarioRequest.getPassword().isEmpty()) {
            Map<String, Object> credentials = new HashMap<>();
            credentials.put("type", "password");
            credentials.put("value", usuarioRequest.getPassword());
            credentials.put("temporary", false);
            payload.put("credentials", Collections.singletonList(credentials));
        }

        String url = String.format("%s/admin/realms/%s/users/%s",
            keycloakProperties.getServerUrl(), keycloakProperties.getRealm(), userId);

        webClient.put()
            .uri(url)
            .headers(h -> h.setBearerAuth(tokenAdmin))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(payload)
            .retrieve()
            .onStatus(HttpStatusCode::isError, clientResponse ->
                clientResponse.bodyToMono(String.class)
                    .flatMap(errorBody -> Mono.error(new RuntimeException("Error actualizando usuario " + userId + ": " + clientResponse.statusCode() + " - " + errorBody)))
            )
            .toBodilessEntity()
            .block();

        log.info("Usuario con ID '{}' actualizado exitosamente.", userId);

        // --- Actualización de roles de cliente ---
        if (usuarioRequest.getRol() != null && !usuarioRequest.getRol().isEmpty()) {
            try {
                // ✅ FORZAR TIPO explícitamente
                Mono<Object> monoRoles = keycloakAdminClient.obtenerRolesClienteDeUsuario(
                    userId, keycloakProperties.getClientName()
                );
                List<Map<String, Object>> currentClientRoles = (List<Map<String, Object>>) monoRoles.block();

                String newRole = usuarioRequest.getRol();
                Set<String> rolesToDelete = new HashSet<>();

                for (Map<String, Object> roleMap : currentClientRoles) {
                    String roleName = (String) roleMap.get("name");
                    if (!roleName.equals(newRole)) {
                        rolesToDelete.add(roleName);
                    }
                }

                for (String role : rolesToDelete) {
                    eliminarRolClienteAUsuario(userId, role);
                    log.debug("Rol de cliente '{}' eliminado del usuario con ID '{}'.", role, userId);
                }

                boolean newRoleExists = currentClientRoles.stream()
                    .anyMatch(roleMap -> newRole.equals(roleMap.get("name")));

                if (!newRoleExists) {
                    asignarRolClienteAUsuario(userId, newRole);
                    log.debug("Rol de cliente '{}' asignado al usuario con ID '{}'.", newRole, userId);
                } else {
                    log.debug("El rol de cliente '{}' ya está asignado al usuario con ID '{}', no se requiere reasignación.", newRole, userId);
                }

                log.info("Roles de cliente del usuario con ID '{}' actualizados a: {}", userId, newRole);

            } catch (Exception e) {
                log.error("Error al actualizar los roles de cliente del usuario con ID '{}': {}", userId, e.getMessage());
                throw new RuntimeException("Fallo al actualizar roles de cliente en Keycloak: " + e.getMessage(), e);
            }
        } else {
            log.info("No se especificó un rol en la solicitud de actualización para el usuario con ID '{}'. Los roles existentes no fueron modificados.", userId);
        }
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


    /**
     * METOD PARA MAPEAR LA RESPUESTA DE KEYCLOAK A KeycloakUserResponse
     * 
     */
    
    

}
