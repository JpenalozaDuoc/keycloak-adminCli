package apikeycloak.tokenization.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import apikeycloak.tokenization.dto.KeycloakUserResponse;
import apikeycloak.tokenization.dto.UsuarioRequest;
import apikeycloak.tokenization.service.KeycloakUserService;

@RestController
@RequestMapping("/api/keycloak/users")
public class KeycloakUserController {

    private final KeycloakUserService keycloakUserService;

    public KeycloakUserController(KeycloakUserService keycloakUserService) {
        this.keycloakUserService = keycloakUserService;
    }

    @PostMapping
    public ResponseEntity<String> crearUsuario(@RequestBody UsuarioRequest usuarioRequest) {
        try {
            keycloakUserService.crearUsuario(usuarioRequest);
            return ResponseEntity.status(HttpStatus.CREATED).body("Usuario creado exitosamente");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + e.getMessage());
        }
    }
    // Listar usuarios, devuelve lista simple (puedes mejorar el DTO o paginación si quieres)
    @GetMapping
    public ResponseEntity<List<KeycloakUserResponse>> listarUsuarios(
            @RequestParam(required = false) String username
    ) {
        List<KeycloakUserResponse> usuarios = keycloakUserService.listarUsuarios(username);
        return ResponseEntity.ok(usuarios);
    }

    // Asignar rol a usuario específico
    @PostMapping("/{userId}/roles")
    public ResponseEntity<String> asignarRol(
            @PathVariable String userId,
            @RequestParam String rol
    ) {
        try {
            keycloakUserService.asignarRolAdmin(userId, rol);
            return ResponseEntity.ok("Rol asignado correctamente");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + e.getMessage());
        }
    }

    @GetMapping("/all")
    public ResponseEntity<List<Map<String, Object>>> listarUsuariosGen(
            @RequestParam(required = false) String username
    ) {
        if (username == null || username.isEmpty()) {
            return ResponseEntity.ok(keycloakUserService.listarUsuariosGenerico());
        } else {
            // Aquí tendrías que tener otro método que liste por username, o implementar lógica adicional.
            // Si no tienes ese método, podrías lanzar excepción o retornar vacío.
            return ResponseEntity.ok(List.of()); // vacío por ejemplo
        }
}


    
}
