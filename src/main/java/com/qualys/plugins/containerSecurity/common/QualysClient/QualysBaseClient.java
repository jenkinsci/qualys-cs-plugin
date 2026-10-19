package com.qualys.plugins.containerSecurity.common.QualysClient;


import com.qualys.plugins.containerSecurity.common.QualysAuth.QualysAuth;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.net.URL;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

class QualysBaseClient {
    private QualysAuth auth;
    protected PrintStream stream;
    protected int timeout = 30; // in seconds


    public QualysBaseClient(QualysAuth auth, PrintStream stream) {
        this.auth = auth;
        this.stream = stream;
    }

    public URL getAbsoluteUrl(String path) throws MalformedURLException {
        path = (path.startsWith("/")) ? path : ("/" + path);
        URL url = new URL(this.auth.getServer() + path);
        return url;
    }

    /**
     * Gateway base URL used for all Qualys API calls (same base as used by OAUTH).
     */
    public String getGatewayBaseUrl() {
        return this.auth.getServer();
    }

    protected boolean isOidcAuth() {
        return String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("OIDC");
    }

    /**
     * Human readable auth type used for logging. OIDC is surfaced as IDP.
     */
    public String getAuthTypeLabel() {
        String type = String.valueOf(this.auth.getAuthType());
        return type.equalsIgnoreCase("OIDC") ? "IDP" : type.toUpperCase(Locale.ROOT);
    }

    protected Map<String, String> getAuthHeaders() throws UnsupportedEncodingException {
        Map<String, String> headers = new HashMap<>();
        headers.put("accept", "application/json");
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("BASIC"))
            return headers;
        else if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("OAUTH")) {
            headers.put("clientId", this.auth.getClientId());
            headers.put("clientSecret", this.auth.getClientSecret());
            return headers;
        } else if (isOidcAuth())
            return headers;
        else
            return null;
    }

    /**
     * Resolves the full URL used for token generation.
     * BASIC/OAUTH use the Qualys gateway auth endpoints; IDP (OIDC) uses the external token URL.
     */
    protected String getAuthUrl(Map<String, String> apiMap) throws MalformedURLException {
        if (isOidcAuth()) {
            String tokenUrl = this.auth.getTokenUrl();
            if (tokenUrl == null || tokenUrl.trim().isEmpty()) {
                throw new IllegalStateException("IDP tokenUrl is required to request an IDP access token.");
            }
            return tokenUrl.trim();
        }
        String endpoint = this.getAuthEndpoint(apiMap);
        return (endpoint == null) ? null : this.getAbsoluteUrl(endpoint).toString();
    }


    protected String getAuthEndpoint(Map<String, String> apiMap) {
        if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("BASIC"))
            return apiMap.get("getAuth");
        else if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("OAUTH"))
            return apiMap.get("getUserLevelOAuth");
        else
            return null;
    }

    protected byte[] getAuthEntity() throws UnsupportedEncodingException {
        if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("BASIC"))
            return this.getBasicAuthJWTEncodedEntity();
        else if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("OAUTH"))
            return new byte[0];
        else if (isOidcAuth())
            return this.getOidcFormEncodedEntity();
        else
            return new byte[0];
    }

    /**
     * Builds the client_credentials form body for the IDP (OIDC) token request.
     */
    protected byte[] getOidcFormEncodedEntity() throws UnsupportedEncodingException {
        StringBuilder body = new StringBuilder("grant_type=client_credentials");
        body.append("&client_id=").append(URLEncoder.encode(this.auth.getClientId(), "UTF-8"));
        body.append("&client_secret=").append(URLEncoder.encode(this.auth.getClientSecret(), "UTF-8"));
        String oidcScope = this.auth.getOidcScope();
        if (oidcScope != null && !oidcScope.trim().isEmpty()) {
            body.append("&scope=").append(URLEncoder.encode(oidcScope, "UTF-8"));
        }
        String audience = this.auth.getAudience();
        if (audience != null && !audience.trim().isEmpty()) {
            body.append("&audience=").append(URLEncoder.encode(audience, "UTF-8"));
        }
        return body.toString().getBytes(StandardCharsets.UTF_8);
    }

    protected byte[] getBasicAuthJWTEncodedEntity() throws UnsupportedEncodingException {
        String userPass = "username=" + java.net.URLEncoder.encode(this.auth.getUsername(), "UTF-8") + "&password=" + java.net.URLEncoder.encode(this.auth.getPassword(), "UTF-8") + "&token=true";
        return userPass.getBytes(StandardCharsets.UTF_8);
    }
    
    protected CloseableHttpClient getHttpClient() {
    	
    	RequestConfig config = RequestConfig.custom()
  	    	  .setConnectTimeout(this.timeout * 1000)
  	    	  .setConnectionRequestTimeout(this.timeout * 1000)
  	    	  .setSocketTimeout(this.timeout * 1000).build(); // Timeout settings
    	
    	final HttpClientBuilder clientBuilder = HttpClients.custom();
    	final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
    	
    	clientBuilder.setDefaultRequestConfig(config);
    	clientBuilder.setDefaultCredentialsProvider(credentialsProvider);    	
    	
    	if(this.auth.getProxyServer() != null && !this.auth.getProxyServer().isEmpty()) { 
    		final HttpHost proxyHost = new HttpHost(this.auth.getProxyServer(),this.auth.getProxyPort()); 	
    		final HttpRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxyHost);
    		clientBuilder.setRoutePlanner(routePlanner);
    		
    		String username = this.auth.getProxyUsername();
            String password = this.auth.getProxyPassword();
            
            if (username != null && !"".equals(username.trim())) {
                System.out.println("Using proxy authentication (user=" + username + ")");                
                credentialsProvider.setCredentials(new AuthScope(proxyHost), 
                								   new UsernamePasswordCredentials(username, password));
            }            
    		
    	}

    	return clientBuilder.build();
    } 
    
    /**
     * This method use to set connection timeout for http client.   
     * @param timeout - int - in secs
     */
    public void setTimeout(int timeout) {
    	this.timeout = timeout;    	
    }
}
