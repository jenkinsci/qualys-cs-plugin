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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class QualysCSClient extends QualysBaseClient {
    HashMap<String, String> apiMap;
    private String token = null;
    private int retryInterval = 5;
    private int retryCount = 5;
    private String tmp_token = "";
    
    private boolean validateSubscription(String jwt) {
    	String[] jwtToken = jwt.split("\\.");
    	Base64.Decoder decoder = Base64.getDecoder();  
        String djwtToken = new String(decoder.decode(jwtToken[1])); 
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

    private CloseableHttpResponse post() throws Exception {
    	CloseableHttpResponse response = null;
    	try {
            String apiPath = this.getAuthEndpoint(this.apiMap);
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request To: " + url.toString());
            CloseableHttpClient httpclient = this.getHttpClient();
            HttpPost postRequest = new HttpPost(url.toString());
            Map<String, String> headers = this.getAuthHeaders();
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                postRequest.addHeader(entry.getKey(), entry.getValue());
            }

            postRequest.setEntity(new ByteArrayEntity(this.getAuthEntity()));
        	response = httpclient.execute(postRequest); 
            
        	System.out.println("Post request status: "+response.getStatusLine().getStatusCode());
		} catch (Exception e) {
			throw e;
        }   
    	return response;
    }
    
    private CloseableHttpResponse getAuthToken() throws Exception {
    	this.stream.println("Generating Auth Token...");
    	String output_msg = "";
    	int timeInterval = 0;
    	CloseableHttpResponse response = null;
	    while(timeInterval < this.retryCount) {
	    	output_msg = "";
	    	try {
                response = this.post();
		    	if(response.getEntity()!=null) {
		            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		            String output;
		            while ((output = br.readLine()) != null) {
		                output_msg += output;
		            }
		    	}
		    	this.tmp_token = output_msg;
		    	this.stream.println("Fetching auth token: Response code: "+response.getStatusLine().getStatusCode());
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
		        		Thread.sleep(this.retryInterval * 1000);
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
        return response;
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
    	CloseableHttpResponse response = null;
    	boolean success = false;
    	try {
    		response = getAuthToken();
	    	boolean isValidToken = false;
            if (response.getStatusLine().getStatusCode() == 201 || response.getStatusLine().getStatusCode() == 200) {
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
	    	} else if (response.getStatusLine().getStatusCode() == 401){
	    		this.stream.println("Connection test failed; "+this.tmp_token);
	    		errorMessage = "Connection test failed; response code : 401; Please provide valid Qualys credentials";
			} else {
				this.stream.println("Error testing connection; "+this.tmp_token);
				errorMessage ="Error testing connection; Server returned: "+ response.getStatusLine().getStatusCode() + "; " + " Invalid inputs or something went wrong with server. Please check API server and/or proxy details.";
			}
	    	
    	} catch (Exception e) {
        	errorMessage = "Error testing connection; Reason: " + e;
        }
    	QualysCSTestConnectionResponse resp = null;
    	if(response != null) {
    		resp = new QualysCSTestConnectionResponse(response.getStatusLine().getStatusCode(), success, errorMessage);
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
	                return apiResponse;
	    		}
	    	}
	    	getRequest.addHeader("Authorization", "Bearer " +  this.token);
	    	response = httpclient.execute(getRequest); 
	    	apiResponse.responseCode = response.getStatusLine().getStatusCode();
	    	if (apiResponse.responseCode == 401 && apiResponse.response.get("message").toString().contains("JWT expired")) {
    	    	this.stream.println("JWT Token is expired. Regenerating token ... ");
        		QualysCSTestConnectionResponse testConnectionResponse = this.testConnection();
        		if(!testConnectionResponse.success) {
	    			apiResponse.errored = true;
	                apiResponse.errorMessage = "Token generation failed";
	                return apiResponse;
	    		}
        		getRequest.addHeader("Authorization", "Bearer " +  this.token);
    	    	response = httpclient.execute(getRequest); 
        	}
	    	if(response.getEntity()!=null) {
	            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
	            String output;
	            while ((output = br.readLine()) != null) {
	                apiResponseString += output;
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
        }  
        return apiResponse;
    }
}