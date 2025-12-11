package com.qualys.plugins.containerSecurity;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;

import com.qualys.plugins.common.QualysAuth.QualysAuth;
import com.qualys.plugins.common.QualysClient.QualysCSClient;
import com.qualys.plugins.common.QualysClient.QualysCSTestConnectionResponse;
import com.qualys.plugins.common.QualysCriteria.QualysCriteria;
import com.qualys.plugins.containerSecurity.model.ProxyConfiguration;
import com.qualys.plugins.containerSecurity.report.ReportAction;
import com.qualys.plugins.containerSecurity.util.Helper;
import com.qualys.plugins.containerSecurity.webhook.Webhook;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.model.Run;
import hudson.model.TaskListener;
import qshaded.com.google.gson.Gson;
import qshaded.com.google.gson.JsonArray;
import qshaded.com.google.gson.JsonElement;
import qshaded.com.google.gson.JsonObject;

public class GetImageVulns {
    private Run<?, ?> run;
    private TaskListener listener;
    private PrintStream buildLogger;
    private QualysCSClient qualysClient;
    private int pollingIntervalForVulns;
    private int vulnsTimeout;
    private boolean isFailConditionsConfigured;
    private String webhookUrl;
    private ProxyConfiguration proxyConfiguration;
    private JsonObject criteria;
    private QualysAuth auth;
    
    private boolean buildSuccess = true;
    private final static Logger logger = Logger.getLogger(GetImageVulns.class.getName());
    
    public GetImageVulns(QualysCSClient client, QualysAuth auth, Run<?, ?> run, TaskListener listener, int pollingIntervalForVulns, int vulnsTimeout, 
    		String webhookUrl, JsonObject criteria, boolean isFailConditionsConfigured, ProxyConfiguration proxyConfiguration) {
        this.run = run;
        this.listener = listener;
        this.buildLogger = listener.getLogger();
        this.pollingIntervalForVulns = pollingIntervalForVulns;
        this.vulnsTimeout = vulnsTimeout;
        this.qualysClient = client;
        this.auth = auth;
        this.criteria = criteria;
        this.isFailConditionsConfigured = isFailConditionsConfigured;
        this.webhookUrl= webhookUrl;
        this.proxyConfiguration = proxyConfiguration;
    }
	
    public void getAndProcessDockerImagesScanResult(HashMap<String, String> imageList, long taggingTime) throws AbortException, QualysEvaluationException {
    	if (imageList == null || imageList.isEmpty()) {
    		return;
    	}
    	
    	try {
    		buildLogger.println("Testing connection with Qualys API server...");
    		logger.info("Testing connection with Qualys API server...");
    		//test connection
    		int retryCount = 0;
    		boolean retry = true;
    		
    		while(retry && retryCount <= 3) {
	    		QualysCSTestConnectionResponse resp = qualysClient.testConnection();
            	logger.info("Received response : " + resp);
            	
	    		retry = false;
	    		retryCount++;
	    		
	    		//JP-210 retry 3 times after 5 sec delay to test connection
	    		if(resp.success == true && (resp.responseCode == 201||resp.responseCode==200)) {
		   			buildLogger.println("Test connection successful.");
	    			logger.info("Test connection successful. Response code: " + resp.responseCode);
	    			break;
		   		}else if((resp.responseCode >= 500 && resp.responseCode <= 599 && retryCount < 3) || (resp.responseCode == 400 && retryCount < 3)) {
    				retry = true;
    				long secInMillis = TimeUnit.SECONDS.toMillis(5);
    				buildLogger.println("Something went wrong with server; Could be a temporary glitch. Retrying in 5 secs...");
    				Thread.sleep(secInMillis);
    				continue;
    			} else {
    				throw new QualysEvaluationException(resp.message);
		   		}
    		}
    	} catch (RuntimeException e) {
    		logger.info("Test connection with Qualys API server failed. Reason : " + e.getMessage());
            throw new QualysEvaluationException("Test connection with Qualys API server failed. Reason : " + e.getMessage());
    	} catch (Exception e) {
    		logger.info("Test connection with Qualys API server failed. Reason : " + e.getMessage());
            throw new QualysEvaluationException("Test connection with Qualys API server failed. Reason : " + e.getMessage());
        }
    	
    	ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(imageList.size());

        //create a list to hold the Future object associated with Callable
    	Map<String, Future<String>> list = new HashMap<String, Future<String>>();
        
        for (String imageSha : imageList.keySet()) {
            //submit Callable tasks to be executed by thread pool
        	Future<String> future = executor.submit(new GetImageVulnsCallable(taggingTime, imageSha, qualysClient, listener, 
        			pollingIntervalForVulns, vulnsTimeout, run.getArtifactsDir().getAbsolutePath(), isFailConditionsConfigured, auth));
            //add Future to the list, we can get return value using Future
            list.put(imageSha, future);
        }
        
        executor.shutdown();
        processResult(imageList, list);
    }
    
    public void processResult(HashMap<String, String> imageList, Map<String, Future<String>> list) throws AbortException, QualysEvaluationException {
    	List<String> exceptionMessages = new ArrayList<String>();
        JsonArray trendingDataObj = new JsonArray();
        JsonObject scanReportObj = new JsonObject();
        JsonObject imageSHA = new JsonObject();
        boolean hasAtleastOneResult = false;
        List<String> otherExceptions = new ArrayList<String>();
        for(Entry<String, String> entry : imageList.entrySet()) {
        	String imageSha = entry.getKey();
        	String imageID = imageSha.substring(0, 12);
        	String response = null;
        	Future<String> future = list.get(imageSha);
        	//JsonObject report = null;
        	try {
        		response = future.get();
        	}catch(Exception e) {
        		if (isFailConditionsConfigured) {
        			//throw new AbortException(e.getMessage());
        			otherExceptions.add(e.getMessage());
        		}
        	}
        	
            if (response == null || response.isEmpty()) {
            	continue;
            }
            try {
            	Gson gson = new Gson();
            	String criteriaString = gson.toJson(criteria);
            	buildLogger.println("Criteria object: " +  criteriaString);
        	
        		String scanResult = response;
    			if (!scanResult.isEmpty()) {
    				hasAtleastOneResult = true;
    				// Added Image SHA256 for create Image summary link on report page. 
    				JsonObject scanResultObj = gson.fromJson(scanResult, JsonObject.class);
    				if (scanResultObj.has("sha"))
    					imageSHA.addProperty(imageID, scanResultObj.get("sha").getAsString());
    				//evaluate scan result against criteria configured          		
        			QualysCriteria criteria2 = new QualysCriteria(criteriaString);
        			buildSuccess = criteria2.evaluate(gson.fromJson(response, JsonObject.class));
        			JsonObject reportObj = criteria2.getResult();
        			
        			//data for summary file - will be used to generate reports
        			scanReportObj.add(imageID, reportObj);
        			JsonObject trend = getTrendingForImage(imageID, reportObj);
        			trendingDataObj.add(trend);
        			//get falilure messages
        			if(!buildSuccess) {
        				String failReason = getBuildFailureMessages(imageID, reportObj);
        				exceptionMessages.add(failReason);
        			}
        			//excluded items logs
        			if(reportObj.getAsJsonObject("qids") != null || reportObj.getAsJsonObject("cveIds") != null) {
        				JsonObject qids = reportObj.getAsJsonObject("qids");
        				if(qids.get("excluded") != null && !qids.get("excluded").isJsonNull() && !StringUtils.isEmpty(qids.get("excluded").getAsString())) {
        					buildLogger.println("Excluded QIDs while evaluating image <" + imageID + "> : " + qids.get("excluded").getAsString());
        				}
        				JsonObject cves = reportObj.getAsJsonObject("cveIds");
        				if(cves.get("excluded") != null && !cves.get("excluded").isJsonNull() && !StringUtils.isEmpty(cves.get("excluded").getAsString())) {
        					buildLogger.println("Excluded CVE IDs while evaluating image <" + imageID + "> : " + cves.get("excluded").getAsString());
        				}
        			}
        		}
        	
            }catch(Exception e){
            	e.printStackTrace();
            	buildLogger.println("Error while processing/evaluating scan result. Error: " + e.getMessage());
            }
        }
        
        if (!hasAtleastOneResult) {
    		if(!otherExceptions.isEmpty()) {
    			throw new AbortException(otherExceptions.stream().collect(Collectors.joining("\n")));
    		}	
    	}
        
        JsonObject summaryObj = new JsonObject();
        summaryObj.add("scanResult", scanReportObj);        
        summaryObj.add("trendingData", trendingDataObj);
        String content = summaryObj.toString();
        Helper.createNewFile(run.getArtifactsDir().getAbsolutePath(), "qualys_images_summary", content, buildLogger);
        
        //create zip file of artifacts
        String buildNo = "";
        try {
        	EnvVars env = run.getEnvironment(listener);
        	buildNo = env.get("BUILD_NUMBER");
        	Helper.createZip(run.getArtifactsDir().getAbsolutePath()+"/qualys_plugin_scanResult-" + buildNo + ".zip", run.getArtifactsDir().getAbsolutePath(), buildLogger);
        } catch (RuntimeException e) {
        	e.printStackTrace();
        	buildLogger.println("Failed to create zip file. Exception: " + e.getMessage());
        } catch(Exception e) {
        	e.printStackTrace();
        	buildLogger.println("Failed to create zip file. Exception: " + e.getMessage());
        }
        
        //create report links
        try {
        	for(Entry<String, String> entry : imageList.entrySet()) {
        		String imageSha = entry.getKey();
            	String imageID = imageSha.substring(0, 12);
            	String originalImageStr = entry.getValue();
            	String imageSHAStr = null;
            	if (imageSHA.has(imageID)) {
            		imageSHAStr = imageSHA.get(imageID).getAsString();
            	}
            	else {
            		imageSHAStr = imageID;
            	}
	    		if (scanReportObj.has(imageID)) {
	    			ReportAction action = new ReportAction(imageID, run, buildLogger, originalImageStr, auth.getPortalURL(), imageSHAStr);
	    			run.addAction(action);
	    		}
	    	}
        } catch(Exception e) {
        	e.printStackTrace();
        	buildLogger.println("Failed to create Qualys Report links. Exception: " + e.getMessage());
        }
        
        //post data to webhook if configured
        try {
	        if(webhookUrl != null && !StringUtils.isEmpty(webhookUrl)) {
	    		postWebhookData(imageList.keySet(), scanReportObj);
	        }
        } catch(Exception e) {
        	e.printStackTrace();
        	buildLogger.println("Failed to post data to webhook. Exception: " + e.getMessage());
        }
        
        buildLogger.println("Qualys Container Scanning Connector - finished.");
        
        if (!otherExceptions.isEmpty()) {
        	exceptionMessages.addAll(otherExceptions);
        }
        
    	if(!exceptionMessages.isEmpty()) {
        	throw new QualysEvaluationException(exceptionMessages.stream().collect(Collectors.joining("\n")));
        }
    }
    
    public JsonObject getTrendingForImage(String imageID, JsonObject reportObj) {
    	JsonObject trend = new JsonObject();
    	trend.addProperty("imageId", imageID);
		//confirmedVulns array
		JsonArray confirmedVulnsArray = new JsonArray();
		JsonObject obj = reportObj.get("confirmedVulnsBySev").getAsJsonObject();
		for(int i=1; i<=5; i++)
			confirmedVulnsArray.add(obj.get(String.valueOf(i)));
		trend.add("confirmedVulns", confirmedVulnsArray);
		//repos
		JsonArray repos = new JsonArray();
		JsonObject imageSummaryObj = reportObj.getAsJsonObject("imageSummary");
		JsonElement repoObj = imageSummaryObj.get("repo");
		if(repoObj != null && !repoObj.isJsonNull()) {
			JsonArray repoArray = repoObj.getAsJsonArray();
			for (int i = 0; i < repoArray.size(); ++i) {
				JsonObject repo = repoArray.get(i).getAsJsonObject();
				JsonElement repoNameObj = repo.get("repository");
				if (repoNameObj != null && !repoNameObj.isJsonNull()) {
					repos.add(repoNameObj.getAsString());
				}
				
			}
		}
		trend.add("repos", repos);
		return trend;
    }
    
    public void postWebhookData(Set<String> imageList, JsonObject scanReportObj) {
    	String buildNo = "";
        String jobName = "";
        String jobUrl = "";
        try {
        	EnvVars env = run.getEnvironment(listener);
        	buildNo = env.get("BUILD_NUMBER");
        	jobName = env.get("JOB_NAME");
        	jobUrl = env.get("JOB_URL");
        } catch (RuntimeException e) {
        	buildLogger.println("Failed to fetch build number from environment variables");
        } catch(Exception e) {
        	buildLogger.println("Failed to fetch build number from environment variables");
        }
    	
    	
    	//Add reports link for all image ids + webhook
    	JsonObject webhookPostData = new JsonObject();
    	webhookPostData.addProperty("buildNumber", buildNo);
    	webhookPostData.addProperty("jobName", jobName);
    	webhookPostData.addProperty("jobUrl", jobUrl);
    	webhookPostData.addProperty("buildStatus", buildSuccess ? "Success" : "Failed");
    	
    	Gson gson = new Gson();
    	
    	JsonArray imagesDataWebhookArray = new JsonArray();
    	JsonArray failReasonsArray = new JsonArray();
    	for(String imageID: imageList) {
        	JsonObject obj = makeFailReasonObject(imageID, scanReportObj);
        	failReasonsArray.add(obj);
    		JsonObject el = makeWebhookDataObject(imageID, scanReportObj);
    		imagesDataWebhookArray.add(el);
    	}
    	if(!buildSuccess) {
    		webhookPostData.add("failReason", gson.toJsonTree(failReasonsArray));
    	}
    	webhookPostData.add("images", imagesDataWebhookArray);
    	
    	if(!webhookPostData.isJsonNull() && webhookUrl != null && !StringUtils.isEmpty(webhookUrl)) {
    		Webhook wh = new Webhook(webhookUrl, gson.toJson(webhookPostData), buildLogger, proxyConfiguration);
    		wh.post();
    	}
    }
    
	public JsonObject makeFailReasonObject(String imageId, JsonObject scanReportObj) {
    	JsonObject returnObj = new JsonObject();
    	returnObj.addProperty("imageId", imageId);
    	try {
			JsonObject jsonObj = scanReportObj.getAsJsonObject(imageId);
			//severity
			JsonObject severityObj = jsonObj.get("severities").getAsJsonObject();
			JsonObject severityNewObj = null;
			for (Entry<String, JsonElement> el : severityObj.entrySet()) {
				JsonObject sev = el.getValue().getAsJsonObject();
				if(!sev.get("result").getAsBoolean()) {
					if(severityNewObj == null) severityNewObj = new JsonObject();
					JsonObject obj = new JsonObject();
					obj.add("configured", sev.get("configured"));
					obj.add("found", sev.get("found"));
					severityNewObj.add(el.getKey(), obj);
				}
			}
			if(severityNewObj != null) {
				returnObj.add("severity", severityNewObj);
			}
			
			//qid
			JsonObject qidObj = jsonObj.get("qids").getAsJsonObject();
			JsonObject qidNewObj = null;
			if(! qidObj.get("result").getAsBoolean()) {
				qidNewObj = new JsonObject();
				qidNewObj.add("configured", qidObj.get("configured"));
				qidNewObj.add("found", qidObj.get("found"));
			}
			if(qidNewObj != null) {
				returnObj.add("qid", qidNewObj);
			}
			
			//cve
			JsonObject cveObj = jsonObj.get("cveIds").getAsJsonObject();
			JsonObject cveNewObj = null;
			if(! cveObj.get("result").getAsBoolean()) {
				cveNewObj = new JsonObject();
				cveNewObj.add("configured", cveObj.get("configured"));
				cveNewObj.add("found", cveObj.get("found"));
			}
			if(cveNewObj != null) {
				returnObj.add("cve", cveNewObj);
			}
			
			//cvss
			JsonObject cvssObj = jsonObj.get("cvss").getAsJsonObject();
			JsonObject cvssNewObj = null;
			if(! cvssObj.get("result").getAsBoolean()) {
				cvssNewObj = new JsonObject();
				cvssNewObj.add("configured", cvssObj.get("configured"));
				cvssNewObj.add("found", cvssObj.get("found"));
				if (cvssObj.has("version") && cvssObj.get("version").getAsString().equalsIgnoreCase("3")) {					
					cvssNewObj.addProperty("version", 3);
				}else {					
					cvssNewObj.addProperty("version", 2);
				}
			}
			if(cvssNewObj != null) {
				returnObj.add("cvss", cvssNewObj);
			}
			
			//software
			JsonObject softwareObj = jsonObj.get("software").getAsJsonObject();
			JsonObject softwareNewObj = null;
			if(! softwareObj.get("result").getAsBoolean()) {
				softwareNewObj = new JsonObject();
				softwareNewObj.add("configured", softwareObj.get("configured"));
				softwareNewObj.add("found", softwareObj.get("found"));
			}
			if(softwareNewObj != null) {
				returnObj.add("software", softwareNewObj);
			}
        } catch (RuntimeException e) {
    		logger.info("Error while making webhook data : " + e.getMessage());
    		e.printStackTrace();
    	}catch(Exception e) {
    		logger.info("Error while making webhook data : " + e.getMessage());
    		e.printStackTrace();
    	}
    	return returnObj;
    }
    
    public JsonObject makeWebhookDataObject(String imageId, JsonObject scanReportObj) {
		JsonObject result = new JsonObject();
		try {
			JsonObject jsonObj = scanReportObj.getAsJsonObject(imageId);
			JsonObject imageSummaryObj = jsonObj.getAsJsonObject("imageSummary");
			result.addProperty("imageId", imageId);
			result.add("uuid", imageSummaryObj.get("uuid"));
			result.add("sha", imageSummaryObj.get("sha"));
			result.add("size", imageSummaryObj.get("size"));
			result.add("repo", imageSummaryObj.get("repo"));
			result.add("operatingSystem", imageSummaryObj.get("operatingSystem"));
			result.add("layersCount", imageSummaryObj.get("layersCount"));
			result.add("dockerVersion", imageSummaryObj.get("dockerVersion"));
			result.add("architecture", imageSummaryObj.get("architecture"));
			
			JsonObject vulns = new JsonObject();
			vulns.add("totalVulnerabilities", jsonObj.get("totalVulnerabilities"));
			vulns.add("typeDetected", jsonObj.get("typeDetected"));
			
			JsonObject severity = new JsonObject();
			severity.add("Potential", jsonObj.get("potentialVulnsBySev"));
			severity.add("Confirmed", jsonObj.get("confirmedVulnsBySev"));
			vulns.add("severity", severity);
			
			vulns.add("patchable", jsonObj.get("patchability"));
			
			result.add("vulnerabilities", vulns); 
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return result;
    }
    
    private String getBuildFailureMessages(String imageID, JsonObject result) throws Exception {
    	List<String> failureMessages = new ArrayList<String>();
		if(result.has("qids") && result.get("qids") != null && !result.get("qids").isJsonNull()) {
    		JsonObject qidsObj = result.get("qids").getAsJsonObject();
    		boolean qidsPass = qidsObj.get("result").getAsBoolean();
    		if(!qidsPass) {
    			String found = qidsObj.get("found").getAsString();
    			failureMessages.add("QIDs configured in Failure Conditions were found in the scan result of image " + imageID +" : " + found );
    		}
		}
		if(result.has("cveIds") && result.get("cveIds") != null && !result.get("cveIds").isJsonNull()) {
    		JsonObject cveObj = result.get("cveIds").getAsJsonObject();
    		boolean cvePass = cveObj.get("result").getAsBoolean();
    		if(!cvePass) {
    			String found = cveObj.get("found").getAsString();
    			failureMessages.add("CVE IDs configured in Failure Conditions were found in the scan result of image " + imageID +" : " + found );
    		}
		}
		if(result.has("software") && result.get("software") != null && !result.get("software").isJsonNull()) {
    		JsonObject obj = result.get("software").getAsJsonObject();
    		boolean criteriaPass = obj.get("result").getAsBoolean();
    		if(!criteriaPass) {
    			String found = obj.get("found").getAsString();
    			failureMessages.add("Softwares configured in Failure Conditions were found in the scan result of image " + imageID +" : " + found );
    		}
		}
		StringBuffer sevConfigured = new StringBuffer();
		sevConfigured.append("\nConfigured : ");
		String sevFound = "\nFound : ";
		boolean severityFailed = false;
		for(int i=1; i<=5; i++) {
    		if(result.has("severities") && result.get("severities") != null && !result.get("severities").isJsonNull()) {
    			JsonObject sevObj = result.get("severities").getAsJsonObject();
    			JsonObject severity = sevObj.get(""+i).getAsJsonObject();
    			if(severity.has("configured") && !severity.get("configured").isJsonNull() && severity.get("configured").getAsInt() != -1) {
	    			sevFound += "Severity "+ i +": "+ (severity.get("found").isJsonNull() ? 0 : severity.get("found").getAsString()) + ";";
	    			sevConfigured.append("Severity "+ i +">"+ severity.get("configured").getAsString() + ";");
		    		boolean sevPass = severity.get("result").getAsBoolean();
		    		if(!sevPass) {
		    			severityFailed = true;
		    		}
    			}
    		}
		}
		if(result.has("cvss") && result.get("cvss") != null && !result.get("cvss").isJsonNull()) {
    		JsonObject cvssObj = result.get("cvss").getAsJsonObject();
    		boolean cvssPass = cvssObj.get("result").getAsBoolean();
    		if(!cvssPass) {
//    			String found = cvssObj.get("found").getAsString();    			
    			String found = cvssObj.get("foundMap").getAsJsonObject().toString().replaceAll("[{}]", "");
    			failureMessages.add("CVSS Score configured in Failure Conditions were found in the scan result of image " + imageID +" : " + found );
    		}
		}
		if(severityFailed) {
			failureMessages.add("The vulnerabilities count by severity for image id " + imageID + " exceeded one of the configured threshold value :" + sevConfigured.toString() + sevFound);
		}
		
		return StringUtils.join(failureMessages, "\n");
	}
}