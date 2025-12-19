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
import java.net.URL;
import java.util.HashMap;
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
        } else
            return null;
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
        else
            return null;
    }

    protected byte[] getBasicAuthJWTEncodedEntity() throws UnsupportedEncodingException {
        String userPass = "username=" + java.net.URLEncoder.encode(this.auth.getUsername(), "UTF-8") + "&password=" + java.net.URLEncoder.encode(this.auth.getPassword(), "UTF-8") + "&token=true";
        return userPass.getBytes();
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
