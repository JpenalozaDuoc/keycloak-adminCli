package apikeycloak.tokenization.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

    private String tokenUri; //keycloak.token-uri=https://vetcare360.duckdns.org/realms/vetcare360/protocol/openid-connect/token
    private String clientId;    //keycloak.client-id=vetcare-app-service
    private String clientSecret;    //keycloak.client-secret=mdPFoNqBDe97jq4o1ZoCFsOFDWdf5JjD
    private String adminUrl;    //keycloak.admin-url=https://vetcare360.duckdns.org/admin/realms/vetcare360
    private String realm;   //keycloak.realm=vetcare360
    private String clientName;  //keycloak.client-name=vetcare-app
    private String serverUrl;   //keycloak.server-url=ttps://vetcare360.duckdns.org
    
    // Getters y Setters
    public String getTokenUri() {
        return tokenUri;
    }

    public void setTokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAdminUrl() {
        return adminUrl;
    }

    public void setAdminUrl(String adminUrl) {
        this.adminUrl = adminUrl;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }
}
