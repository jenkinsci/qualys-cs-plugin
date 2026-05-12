package com.qualys.plugins.containerSecurity.common.QualysClient;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.qualys.plugins.containerSecurity.common.QualysAuth.QualysAuth;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;

import java.io.*;
import java.net.SocketException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

@SuppressFBWarnings(value = "REC_CATCH_EXCEPTION", justification = "Catching Exception is intentional for graceful error handling")
public class QualysCSClient extends QualysBaseClient {
    HashMap<String, String> apiMap;
    private String token = null;
    private int retryInterval = 5;
    private int retryCount = 5;
    private String tmp_token = "";
    
    private boolean validateSubscription(String jwt) {
    	String[] jwtToken = jwt.split("\\.");
    	Base64.Decoder decoder = Base64.getDecoder();  
        String djwtToken = new String(decoder.decode(jwtToken[1]), StandardCharsets.UTF_8); 
        Gson gson = new Gson();
        JsonObject decodedjwtToken = gson.fromJson(djwtToken, JsonObject.class);
        if (decodedjwtToken.has("modulesAllowed")) {
        	if (decodedjwtToken.get("modulesAllowed").toString().contains("\"CS\"")) {
        		System.out.println("CS Module Found");
        		return true;
        	}
        }
        this.stream.println("CS Module Not Found");
        return false;
    }

    private PostResponse post() throws IOException {
        String apiPath = this.getAuthEndpoint(this.apiMap);
        if (apiPath == null) {
            throw new IOException("API path for authentication endpoint is null");
        }
        URL url = this.getAbsoluteUrl(apiPath);
        this.stream.println("Making Request To: " + url.toString());
        try (CloseableHttpClient httpclient = this.getHttpClient()) {
            HttpPost postRequest = new HttpPost(url.toString());
            Map<String, String> headers = this.getAuthHeaders();
            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    postRequest.addHeader(entry.getKey(), entry.getValue());
                }
            }

            postRequest.setEntity(new ByteArrayEntity(this.getAuthEntity()));
            try (CloseableHttpResponse response = httpclient.execute(postRequest)) {
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = "";
                if (response.getEntity() != null) {
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), StandardCharsets.UTF_8))) {
                        String output;
                        StringBuilder sb = new StringBuilder();
                        while ((output = br.readLine()) != null) {
                            sb.append(output);
                        }
                        responseBody = sb.toString();
                    }
                }
                System.out.println("Post request status: " + statusCode);
                return new PostResponse(statusCode, responseBody);
            }
        }
    }
    
    private static class PostResponse {
        final int statusCode;
        final String responseBody;
        
        PostResponse(int statusCode, String responseBody) {
            this.statusCode = statusCode;
            this.responseBody = responseBody;
        }
    }
    
    private PostResponse getAuthToken() throws Exception {
    	this.stream.println("Generating Auth Token...");
    	int timeInterval = 0;
    	PostResponse postResponse = null;
	    while(timeInterval < this.retryCount) {
	    	try {
                postResponse = this.post();
		    	this.tmp_token = postResponse.responseBody;
		    	this.stream.println("Fetching auth token: Response code: "+postResponse.statusCode);
	    		break;
			} catch (SocketException e) {
				this.stream.println("SocketException : "+e);
				throw e;
	        } catch (IOException e) {
	        	this.stream.println("IOException : "+e);
	        	throw e;
	        } catch (Exception e) {
	        	this.stream.println("Exception : "+e);
	        	
	        	// Handling Empty response and empty response code here
	        	timeInterval++;
	        	if(timeInterval < this.retryCount) {
		        	try {
		        		this.stream.println("Retry fetching auth token ...");
		        		Thread.sleep(this.retryInterval * 1000L);
		        	} catch (Exception e1) {
		            	this.stream.println("Exception : "+e1);
		            	throw e1;
		        	}
	        	}
	        	else {
	        		throw e;
	        	}
	        	
	        }
	    }
        return postResponse;
    }

    public QualysCSClient(QualysAuth auth) {
        super(auth, System.out);
        this.populateApiMap();
    }

    public QualysCSClient(QualysAuth auth, PrintStream stream) {
        super(auth, stream);
        this.populateApiMap();
    }

    private void populateApiMap() {
        this.apiMap = new HashMap<>();
        this.apiMap.put("getAuth", "/auth");
        this.apiMap.put("getUserLevelOAuth", "/auth/oidc");
        this.apiMap.put("getSubscriptionLevelOAuth", "/auth/oidc");
        this.apiMap.put("getImageDetails", "/csapi/v1.3/images/");
        this.apiMap.put("getImages", "/csapi/v1.3/images");
    }

    public QualysCSResponse getImageDetails(String imageSha) {
        return this.get(this.apiMap.get("getImageDetails") + imageSha);
    } // getImageDetails
    
    public QualysCSResponse getImages(String imageSha, long nowMinusSeconds) throws UnsupportedEncodingException {
        return this.get(this.apiMap.get("getImages") + "?filter="+java.net.URLEncoder.encode("sha:" + imageSha + " and lastScanned: [now-"+nowMinusSeconds+"s ... now]",  "UTF-8"));
    } // getImages
    
    public QualysCSTestConnectionResponse testConnection() {
    	String errorMessage = "";
    	PostResponse postResponse = null;
    	boolean success = false;
    	try {
    		postResponse = getAuthToken();
	    	boolean isValidToken = false;
            if (postResponse.statusCode == 201 || postResponse.statusCode == 200) {
	    		this.stream.println("Token Generation SUCCESSFULL");
	    		isValidToken = validateSubscription(this.tmp_token);
	    	
		    	if (isValidToken) {
		    		this.token = this.tmp_token;
		    		this.tmp_token = "";
		    		success = true;
		    	}
		    	else {
		    		errorMessage = "Error Token validation FAIL. CS module is not activated for provided user.";
		    		success = false;
		    		this.stream.println("Token validation FAIL");
		    	}
	    	} else if (postResponse.statusCode == 401){
	    		this.stream.println("Connection test failed; "+this.tmp_token);
	    		errorMessage = "Connection test failed; response code : 401; Please provide valid Qualys credentials";
			} else {
				this.stream.println("Error testing connection; "+this.tmp_token);
				errorMessage ="Error testing connection; Server returned: "+ postResponse.statusCode + "; " + " Invalid inputs or something went wrong with server. Please check API server and/or proxy details.";
			}
	    	
    	} catch (Exception e) {
        	errorMessage = "Error testing connection; Reason: " + e;
        }
    	QualysCSTestConnectionResponse resp = null;
    	if(postResponse != null) {
    		resp = new QualysCSTestConnectionResponse(postResponse.statusCode, success, errorMessage);
    	}
    	else {
    		resp = new QualysCSTestConnectionResponse(0, success, errorMessage);
    	}
 		return resp;
    }
    
    private QualysCSResponse get(String apiPath) {
    	QualysCSResponse apiResponse = new QualysCSResponse();
    	String apiResponseString = "";
        CloseableHttpClient httpclient = null;
        CloseableHttpResponse response = null;
        try {
	        URL url = this.getAbsoluteUrl(apiPath);
	        this.stream.println("Making Get Request for URL: " + url.toString());
	        httpclient = this.getHttpClient();	
	        HttpGet getRequest = new HttpGet(url.toString());
	    	getRequest.addHeader("accept", "application/json");
	    	if (this.token == null) {
	    		QualysCSTestConnectionResponse testConnectionResponse = this.testConnection();
	    		if(!testConnectionResponse.success) {
	    			apiResponse.errored = true;
	                apiResponse.errorMessage = "Token generation failed";
	    		}
	    	}
	    	if (!apiResponse.errored) {
	    		getRequest.addHeader("Authorization", "Bearer " +  this.token);
	    		response = httpclient.execute(getRequest); 
	    		apiResponse.responseCode = response.getStatusLine().getStatusCode();
	    		if (apiResponse.responseCode == 401 && apiResponse.response.get("message").toString().contains("JWT expired")) {
    	    		this.stream.println("JWT Token is expired. Regenerating token ... ");
        			QualysCSTestConnectionResponse testConnectionResponse = this.testConnection();
        			if(!testConnectionResponse.success) {
	    				apiResponse.errored = true;
	                	apiResponse.errorMessage = "Token generation failed";
	    			} else {
        				getRequest.addHeader("Authorization", "Bearer " +  this.token);
    	    			response = httpclient.execute(getRequest); 
	    			}
        		}
	    	}
	    	if(response != null && response.getEntity()!=null) {
	            try (BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), StandardCharsets.UTF_8))) {
	                String output;
	                StringBuilder sb = new StringBuilder();
	                while ((output = br.readLine()) != null) {
	                    sb.append(output);
	                }
	                apiResponseString = sb.toString();
	            }
	
	            JsonParser jsonParser = new JsonParser();
	            JsonElement jsonTree = jsonParser.parse(apiResponseString);
	            if (!jsonTree.isJsonObject()) {
	                throw new InvalidAPIResponseException();
	            }	  
	            apiResponse.response = jsonTree.getAsJsonObject();
	    	}    
	    	
        } catch (Exception e) {
            apiResponse.errored = true;
            apiResponse.errorMessage = e.getMessage();
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException e) {
                    this.stream.println("Error closing response: " + e.getMessage());
                }
            }
            if (httpclient != null) {
                try {
                    httpclient.close();
                } catch (IOException e) {
                    this.stream.println("Error closing httpclient: " + e.getMessage());
                }
            }
        }
        return apiResponse;
    }
}