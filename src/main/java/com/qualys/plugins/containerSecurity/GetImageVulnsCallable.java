package com.qualys.plugins.containerSecurity;

import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;


import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.containerSecurity.common.QualysAuth.QualysAuth;
import com.qualys.plugins.containerSecurity.common.QualysClient.QualysCSClient;
import com.qualys.plugins.containerSecurity.common.QualysClient.QualysCSResponse;
import com.qualys.plugins.containerSecurity.util.Helper;

import hudson.AbortException;
import hudson.model.TaskListener;


public class GetImageVulnsCallable implements Callable<String> {
  
    private String imageId;
    private String imageSha;
    private PrintStream buildLogger; 
    private int pollingIntervalForVulns;
    private int vulnsTimeout;
    public Set<String> reposArray;
    private String buildDirPath;
    private boolean isFailConditionsConfigured;
    private QualysCSClient qualysClient;
    private long taggingTime;
    
    private final static Logger logger = Logger.getLogger(GetImageVulnsCallable.class.getName());
    
    public GetImageVulnsCallable(long taggingTime, String imageSha, QualysCSClient qualysClient, TaskListener listener, 
    		int pollingIntervalForVulns, int vulnsTimeout, String buildDirPath, boolean isFailConditionsConfigured, QualysAuth auth) throws AbortException {
        this.taggingTime = taggingTime;
        this.imageSha = imageSha;
    	this.imageId = imageSha.substring(0,12);
        this.buildLogger = listener.getLogger();
        this.pollingIntervalForVulns = pollingIntervalForVulns;
        this.vulnsTimeout = vulnsTimeout;
        this.buildDirPath = buildDirPath;
        this.isFailConditionsConfigured = isFailConditionsConfigured;
        this.qualysClient = qualysClient;
    }
    
    @Override
    public String call() throws QualysEvaluationException, Exception {
    	buildLogger.println("Thread for Image Id  = "+ imageId + ", " + Thread.currentThread().getName()+" Started");
    	try {
			return fetchScanResult();
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
    }

    public String fetchScanResult() throws QualysEvaluationException, Exception {
    	String scanResult = null;
    	long startTime = System.currentTimeMillis();
    	long vulnsTimeoutInMillis = TimeUnit.SECONDS.toMillis(vulnsTimeout);
    	long pollingInMillis = TimeUnit.SECONDS.toMillis(pollingIntervalForVulns);
    	Instant instant = Instant.now();
		long currentTime = instant.getEpochSecond();
		buildLogger.println("***Current Epoch Time in seconds = " + currentTime);
    	long nowMinusSeconds = currentTime - taggingTime;
    	//Keep checking if the scan results are available at polling intervals, until TIMEOUT_PERIOD is reached or results are available
    	try {
	    	while ((scanResult = getScanReport(imageSha, nowMinusSeconds)) == null ) {
	    		long endTime = System.currentTimeMillis();
	    		if ((endTime - startTime) > vulnsTimeoutInMillis) {
	    			buildLogger.println("Failed to get scan result; timeout of " + vulnsTimeout + " seconds reached. Please check if image " + imageId + " is synced with API server.");
	    			if (isFailConditionsConfigured) {
	    				throw new QualysEvaluationException("Timeout reached fetching scan result for image "+ imageId); 
	    			} else {
	    				break;
	    			}
	    		}
	    		try {
	    			buildLogger.println("Waiting for " + pollingIntervalForVulns + " seconds before making next attempt for " + imageId + " ...");
	    			Thread.sleep(pollingInMillis);
	    			nowMinusSeconds = nowMinusSeconds + pollingIntervalForVulns;
	    		} catch(InterruptedException e) {
	    			buildLogger.println("Error waiting for scan result..");
	    		}
	    	}
    	}
    	catch(Exception e) {
    		throw e;
    	} 
	    
    	if (!(scanResult == null || scanResult.isEmpty())) {
			Helper.createNewFile(buildDirPath, "qualys_" + imageId, scanResult, buildLogger);
    	} else {
    		if (isFailConditionsConfigured) {
    			throw new Exception("No vulnerabilities data for image " + imageId + " found.");
    		} else {
    			buildLogger.println("No vulnerabilities data for image " + imageId + " found.");
    			return null;
    		}
    	}
    	return scanResult;
    }

	private String getScanReport(String imageSha, long nowMinusSeconds) throws Exception {
	
	  	try {
    		//buildLogger.println(new Timestamp(System.currentTimeMillis()) + " ["+ Thread.currentThread().getName() +"] - Calling API: "+ auth.getServer() + String.format(Helper.GET_SCAN_RESULT_API_PATH_FORMAT , imageId));
    	
    		QualysCSResponse resp = null;
            resp = qualysClient.getImages(imageSha, nowMinusSeconds);
    	    logger.info("Received response code: " + resp.responseCode);
    	 
    	    if (resp.responseCode == 400) {
    	    	buildLogger.println("Bad request. response code: "+resp.responseCode+ " Message: "+resp.response.get("message").toString());
    	    	return null;
        	}
  	    
    	    //JP-210 -> continue polling for 5XX response code (common library returns 500 response with resp.errored=true)
    	    if(resp.responseCode >= 500 && resp.responseCode <= 599) {
    	    	buildLogger.println("HTTP Code: " + resp.responseCode + ". Image: N/A. Vulnerabilities: N/A.");
    	    	buildLogger.println("Waiting for image data from Qualys for image id " + imageId);
				return null;
			}
    	    
    	    if(resp.errored) {
    	    	logger.info("Qualys API server URL is not correct or it is not reachable. Error message: " + resp.errorMessage);
        		throw new Exception("Qualys API server URL is not correct or it is not reachable. Error message: " + resp.errorMessage);
    	    }
    	    
			//buildLogger.println("Get scan result API for image " + imageId + " returned code : " + resp.responseCode + "; ");
			if(resp.responseCode == HttpURLConnection.HTTP_NO_CONTENT) {
				buildLogger.println("Waiting for image data from Qualys for image id " + imageId);
				buildLogger.println("HTTP Code: "+ resp.responseCode +". Image details for "+ imageId + " last scanned within last " + nowMinusSeconds + " seconds not found yet.");
				return null;
			}else if(resp.responseCode == HttpURLConnection.HTTP_OK && resp.response != null) {
				buildLogger.println("HTTP Code: "+ resp.responseCode +". Data available; Now fetching image details for imageId " + imageId);
				resp = qualysClient.getImageDetails(imageSha);
				JsonObject jsonObj = resp.response;
				String scanResult = jsonObj.toString();
				JsonElement vulns = jsonObj.get("vulnerabilities");
				if (vulns == null || vulns.isJsonNull()) {
					buildLogger.println("Waiting for vulnerabilities data from Qualys for image id " + imageId);
					buildLogger.println("HTTP Code: 200. Image: known to Qualys. Vulnerabilities: To be processed.");
					return null;
				}
				return scanResult;
			} else {
				buildLogger.println("HTTP Code: "+ resp.responseCode +". Image: Not known to Qualys. Vulnerabilities: To be processed." +". API Response : " + resp.response);
				return null;
			}
    	} catch (QualysTaggingFailException e) {
    		buildLogger.println("Error: "+e.getMessage());
    		throw e;
    	} catch (Exception e) {
     		logger.info("Error fetching scan report for image "+ imageId +", reason : " + e.getMessage());
    		buildLogger.println("Error fetching scan report for image "+ imageId +", reason : " + e.getMessage());
    	} 
    	return null;
    }

    @Override
    public String toString(){
        return this.imageId;
    }
}

