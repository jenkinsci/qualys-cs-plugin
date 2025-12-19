package com.qualys.plugins.containerSecurity.common.QualysAuth;


import java.util.ArrayList;
import java.util.List;

public class QualysAuth {
    AuthType authType;
    private String server;
    private String username;
    private String password;
    private String clientId;
    private String clientSecret;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private String proxyPassword;
    private int proxyPort;

    private String gatewayURL = null;
    public static final List<String> serverPlatformURL = new ArrayList<String>();
    public static final List<String> serverApiURL = new ArrayList<String>();
    public static final List<String> serverGatewayURL = new ArrayList<String>();

    public QualysAuth() {

    }

    static {
        serverPlatformURL.add("https://qualysguard.qualys.com");
        serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.com");
        serverPlatformURL.add("https://qualysguard.qg3.apps.qualys.com");
        serverPlatformURL.add("https://qualysguard.qg4.apps.qualys.com");
        serverPlatformURL.add("https://qualysguard.qualys.eu");
        serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.eu");
        serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.in");
        serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.ca");
        serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.ae");
        serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.co.uk");
        serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.com.au");
        serverPlatformURL.add("https://qualysguard.qg1.apps.qualysksa.com");


        serverApiURL.add("https://qualysapi.qualys.com");
        serverApiURL.add("https://qualysapi.qg2.apps.qualys.com");
        serverApiURL.add("https://qualysapi.qg3.apps.qualys.com");
        serverApiURL.add("https://qualysapi.qg4.apps.qualys.com");
        serverApiURL.add("https://qualysapi.qualys.eu");
        serverApiURL.add("https://qualysapi.qg2.apps.qualys.eu");
        serverApiURL.add("https://qualysapi.qg1.apps.qualys.in");
        serverApiURL.add("https://qualysapi.qg1.apps.qualys.ca");
        serverApiURL.add("https://qualysapi.qg1.apps.qualys.ae");
        serverApiURL.add("https://qualysapi.qg1.apps.qualys.co.uk");
        serverApiURL.add("https://qualysapi.qg1.apps.qualys.com.au");
        serverApiURL.add("https://qualysapi.qg1.apps.qualysksa.com");

        serverGatewayURL.add("https://gateway.qg1.apps.qualys.com");
        serverGatewayURL.add("https://gateway.qg2.apps.qualys.com");
        serverGatewayURL.add("https://gateway.qg3.apps.qualys.com");
        serverGatewayURL.add("https://gateway.qg4.apps.qualys.com");
        serverGatewayURL.add("https://gateway.qg1.apps.qualys.eu");
        serverGatewayURL.add("https://gateway.qg2.apps.qualys.eu");
        serverGatewayURL.add("https://gateway.qg1.apps.qualys.in");
        serverGatewayURL.add("https://gateway.qg1.apps.qualys.ca");
        serverGatewayURL.add("https://gateway.qg1.apps.qualys.ae");
        serverGatewayURL.add("https://gateway.qg1.apps.qualys.co.uk");
        serverGatewayURL.add("https://gateway.qg1.apps.qualys.com.au");
        serverGatewayURL.add("https://gateway.qg1.apps.qualysksa.com");

    }

    public QualysAuth(String server, String oauthKey) {
        this.authType = AuthType.OAuth;
        this.authKey = oauthKey;
    }

    public String getServer() {
        int pos;
        if (gatewayURL == null) {
            if (server.endsWith("/")) {
                server = server.substring(0, server.length() - 1);
            }
            pos = serverPlatformURL.indexOf(server);
            if (pos == -1) {
                pos = serverApiURL.indexOf(server);
            }
            if (pos == -1) {
                pos = serverGatewayURL.indexOf(server);
            }
            if (pos == -1) {
                gatewayURL = server.replace("https://qualysapi.", "https://qualysgateway.");
            } else {
                gatewayURL = serverGatewayURL.get(pos);
            }
        }

        return gatewayURL;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public AuthType getAuthType() {
        return authType;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getProxyServer() {
        return proxyServer;
    }

    public String getProxyUsername() {
        return proxyUsername;
    }

    public String getProxyPassword() {
        return proxyPassword;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public String getAuthKey() {
        return authKey;
    }

    public String getPortalURL() {
        return server.replace("qualysapi", "qualysguard");
    }

    public void setQualysCredentials(String server, AuthType authType, String username, String password, String clientId, String clientSecret) {
        this.authType = authType;
        this.server = server;
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public void setProxyCredentials(String proxyServer, String proxyUsername, String proxyPassword, int proxyPort) {
        this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.proxyPort = proxyPort;
    }

}
