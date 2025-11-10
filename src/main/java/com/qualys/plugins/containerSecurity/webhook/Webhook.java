package com.qualys.plugins.containerSecurity.webhook;

import java.io.PrintStream;
import java.util.logging.Logger;

import org.apache.http.HttpHost;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.HttpStatus;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.commons.lang.StringUtils;

import com.qualys.plugins.containerSecurity.model.ProxyConfiguration;

import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class Webhook{
	
	private PrintStream buildLogger;
	private final String url;
    private final String data;
    private final ProxyConfiguration proxy;
    
    private static final int timeout = 60;
    private static final int RETRIES = 1;
    private final static Logger logger = Logger.getLogger(Webhook.class.getName());

    public Webhook(String url, String data, PrintStream logger, ProxyConfiguration proxy) {
        this.url = url;
        this.data = data;
        this.buildLogger = logger;
        this.proxy = proxy;
    }
    
    private HttpClient getHttpClient() {
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        CloseableHttpClient client;
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(timeout)
                .setConnectTimeout(timeout)
                .setSocketTimeout(timeout)
                .build();
        if (proxy.getUseProxy()) {
            String username = proxy.getProxyUsername();
            String password = proxy.getProxyPassword();

            if (StringUtils.isNotBlank(username)) {
                credsProvider.setCredentials(
                        new AuthScope(proxy.getProxyServer(), proxy.getProxyPort()),
                        new UsernamePasswordCredentials(username, password)
                );
            }

            HttpHost proxyHost = new HttpHost(proxy.getProxyServer(), proxy.getProxyPort());
            client = HttpClients.custom()
                    .setDefaultCredentialsProvider(credsProvider)
                    .setProxy(proxyHost)
                    .setDefaultRequestConfig(requestConfig)
                    .build();
        } else {
            client = HttpClients.custom()
                    .setDefaultCredentialsProvider(credsProvider)
                    .setDefaultRequestConfig(requestConfig)
                    .build();
        }

        return client;
    }
    
    public void post() {
        int tried = 0;
        boolean success = false;
        HttpClient client = this.getHttpClient();

        buildLogger.println("Sending scanned result data to webhook URL - " + url);
        logger.info("Sending scanned result data to webhook URL - " + url);
        do {
            tried++;
                // uncomment to log what message has been sent
                logger.info("Posted JSON: " + data);
                HttpPost post = new HttpPost(url);
                post.setEntity(new StringEntity(data, "UTF-8"));
                post.setHeader("Content-Type", "application/json");
                // Execute the request
                try (CloseableHttpResponse response = (CloseableHttpResponse) client.execute(post)) {
                    int responseCode = response.getStatusLine().getStatusCode();

                    if (responseCode != HttpStatus.SC_OK) {
                        String responseBody = response.getEntity() != null
                                ? new String(response.getEntity().getContent().readAllBytes())
                                : "";

                        buildLogger.println("Posting data to " + url + " may have failed. Webhook responded with status code - " + responseCode);
                        logger.info("Posting data to " + url + " may have failed. Webhook responded with status code - " + responseCode);
                        logger.info("Message from webhook - " + responseBody);
                    } else {
                        success = true;
                    }
                }
             catch (Exception e) {
            	buildLogger.println("Failed to post data to webhook URL - " + url);
            	logger.info("Failed to post data to webhook URL - " + url);
                e.printStackTrace(buildLogger);
            }
        } while (tried < RETRIES && !success);
        if(success) {
        	buildLogger.println("Successfully posted data to webhook URL - " + url);
        	logger.info("Successfully posted data to webhook URL - " + url);
        }
    }
	
}