package com.qualys.plugins.containerSecurity.common.QualysAuth;


import java.util.ArrayList;
import java.util.List;

public class QualysAuth {
    AuthType authType;
    private String server = "";
    private String username;
    private String password;
    private String clientId;
    private String clientSecret;
    private String tokenUrl;
    private String oidcScope;
    private String audience;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private String proxyPassword;
    private int proxyPort;

    private String gatewayURL = null;
    static final List<String> serverPlatformURL = new ArrayList<String>();
    static final List<String> serverApiURL = new ArrayList<String>();
    static final List<String> serverGatewayURL = new ArrayList<String>();

    public QualysAuth() {

    }

    static {
        serverPlatformURL.add("https://qualysguard.qualys.com");
        serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.com");
        serverPlatformURL.add("https://qualysguard.qg3.apps.qualys.com");
        serverPlatformURL.add("https://qualysguard.qg4.apps.qualys.com");
        serverPlatformURL.add("https://qualysguard.gov1.qualys.us");
        serverPlatformURL.add("https://qualysguard.qualys.eu");
        serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.eu");
        serverPlatformURL.add("https://qualysguard.qg3.apps.qualys.it");
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
        serverApiURL.add("https://qualysapi.gov1.qualys.us");
        serverApiURL.add("https://qualysapi.qualys.eu");
        serverApiURL.add("https://qualysapi.qg2.apps.qualys.eu");
        serverApiURL.add("https://qualysapi.qg3.apps.qualys.it");
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
        serverGatewayURL.add("https://gateway.gov1.qualys.us");
        serverGatewayURL.add("https://gateway.qg1.apps.qualys.eu");
        serverGatewayURL.add("https://gateway.qg2.apps.qualys.eu");
        serverGatewayURL.add("https://gateway.qg3.apps.qualys.it");
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

    private static String normalize(String url) {
        String s = url == null ? "" : url.trim();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static int findPlatformIndex(String url) {
        int pos = serverPlatformURL.indexOf(url);
        if (pos == -1) {
            pos = serverApiURL.indexOf(url);
        }
        if (pos == -1) {
            pos = serverGatewayURL.indexOf(url);
        }
        return pos;
    }

    public static String toGatewayUrl(String url) {
        String s = normalize(url);
        int pos = findPlatformIndex(s);
        if (pos != -1) {
            return serverGatewayURL.get(pos);
        }
        return s.replace("https://qualysapi.", "https://qualysgateway.")
                .replace("https://qualysguard.", "https://qualysgateway.");
    }

    public static String toPortalUrl(String url) {
        String s = normalize(url);
        int pos = findPlatformIndex(s);
        if (pos != -1) {
            return serverPlatformURL.get(pos);
        }
        return s.replace("https://qualysapi.", "https://qualysguard.")
                .replace("https://qualysgateway.", "https://qualysguard.");
    }

    public String getServer() {
        if (gatewayURL == null) {
            server = normalize(server);
            gatewayURL = toGatewayUrl(server);
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

    public String getTokenUrl() {
        return tokenUrl;
    }

    public String getOidcScope() {
        return oidcScope;
    }

    public String getAudience() {
        return audience;
    }

    public void setTokenUrl(String tokenUrl) {
        this.tokenUrl = tokenUrl;
    }

    public void setOidcScope(String oidcScope) {
        this.oidcScope = oidcScope;
    }

    public void setAudience(String audience) {
        this.audience = audience;
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
        return toPortalUrl(server);
    }

    public void setQualysCredentials(String server, AuthType authType, String username, String password, String clientId, String clientSecret) {
        this.authType = authType;
        this.server = server;
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public void setQualysCredentials(String server, AuthType authType, String clientId, String clientSecret, String tokenUrl, String oidcScope, String audience) {
        this.authType = authType;
        this.server = server;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.oidcScope = oidcScope;
        this.audience = audience;
    }

    public void setProxyCredentials(String proxyServer, String proxyUsername, String proxyPassword, int proxyPort) {
        this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.proxyPort = proxyPort;
    }

}
