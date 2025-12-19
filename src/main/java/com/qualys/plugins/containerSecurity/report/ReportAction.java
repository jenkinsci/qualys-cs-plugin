package com.qualys.plugins.containerSecurity.report;

import java.io.File;
import java.io.PrintStream;
import java.lang.reflect.Type;
import java.util.List;
import java.util.logging.Logger;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;

import hudson.Extension;
import hudson.model.Action;
import hudson.model.Run;

@Extension
public class ReportAction implements Action {
    private String dockerImageId;
    private Run<?, ?> run;
    private int prevBuildNumber;
    private JsonObject reportObject;
    private JsonObject trendingData;
    private String imageNameInput;
    private String portalURL;
    private String imageSHA;
    
    public ReportAction() { }
    
    private final static Logger logger = Logger.getLogger(ReportAction.class.getName());

    public ReportAction(String dockerImageId, Run<?, ?> run, PrintStream buildLogger, String imageInput, String portalURL, String imageSHA) {
        this.dockerImageId = dockerImageId;
        this.run = run;
        this.prevBuildNumber = 0;
        this.imageNameInput = imageInput;
        this.portalURL = portalURL;
        this.imageSHA = imageSHA;
    }
    
    public JsonObject getReportJsonObject() {
    	//read reports object(from common library) from file
        String summaryFilename = run.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_images_summary.json";
        try {
	    	File f = new File(summaryFilename);
	    	if(f.exists()){
	    		Gson gson = new Gson();
	    		String resultString = FileUtils.readFileToString(f);
	    		JsonObject obj = gson.fromJson(resultString, JsonObject.class);
	    		JsonObject scanResult = obj.getAsJsonObject("scanResult");
	    		this.reportObject = scanResult.getAsJsonObject(this.dockerImageId);
	    		//get trending data for current image
	    		JsonArray trendingDataArr = obj.getAsJsonArray("trendingData");
	    		for(JsonElement el: trendingDataArr) {
	    			JsonObject trend = el.getAsJsonObject();
	    			String imageId = trend.get("imageId").getAsString();
	    			if(imageId.equals(dockerImageId)) {
	    				this.trendingData = trend;
	    			}
	    		}
	    	}
	    	else {
	    		logger.info("Error: Couldn't find summary file for the build.");
	    	}
        } catch (RuntimeException e) {
        	e.printStackTrace();
    		logger.info("Error while reading summary file: " + e.getMessage());
        }catch(Exception e) {
    		e.printStackTrace();
    		logger.info("Error while reading summary file: " + e.getMessage());
    	}
    	JsonObject totalVulnsTrend = getTotalVulnsTrend();
    	reportObject.add("totalVulnsTrend", totalVulnsTrend);
    	return reportObject;
    }
    
    public JsonObject getTotalVulnsTrend() {
    	Gson gson = new Gson();
    	JsonObject obj = new JsonObject();
    	JsonArray rposArr = trendingData.get("repos").getAsJsonArray();
    	JsonArray vulnsArr = trendingData.get("confirmedVulns").getAsJsonArray();
    	JsonArray totalVulns = gson.fromJson(vulnsArr, JsonArray.class);
    	obj.add("current", totalVulns);
    	obj.addProperty("prevBuildNumber", prevBuildNumber);
    	obj.addProperty("addChart", "1");
    	obj.addProperty("prev", "null");
    	if(rposArr == null) {
    		obj.addProperty("addChart", "0");
    	}
    	
    	JsonArray prevRunSummary = null;
        Run<?, ?> prevRun = run;
    	
    	while(prevRun != null && prevRun.getPreviousBuild() != null) {
	        try {
	        	prevRun = prevRun.getPreviousBuild();
	        	if (prevRun != null) {
	        		String filename = prevRun.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_images_summary.json";
		        	File f = new File(filename);
		        	if(f.exists()){
		        		prevBuildNumber = prevRun.number;
		        		//read file and get values
		        		String result = FileUtils.readFileToString(f);
			    		JsonObject obj1 = gson.fromJson(result, JsonObject.class);
			    		prevRunSummary = obj1.getAsJsonArray("trendingData");
		        		break;
		        	}
	        	}
	        } catch (RuntimeException e) {
	            break;	
	        }catch(Exception e){
	        	break;
	        }
        }
    	if(prevRunSummary != null && !prevRunSummary.isJsonNull() && rposArr != null)  {
	    	Type listType = TypeToken.getParameterized(List.class, String.class).getType();
	    	List<String> currRepos = gson.fromJson(rposArr.toString(), listType);
	    	//compare repos to get matched vulnscount
	    	for(JsonElement el: prevRunSummary) {
	    		JsonObject rpoObj = el.getAsJsonObject();
	    		if(rpoObj.get("repos").getAsJsonArray().size() > 0) {
	    			JsonArray repoString = rpoObj.get("repos").getAsJsonArray();
	    			List<String> prevRepos = gson.fromJson(repoString.toString(), listType);
	    			if(currRepos.containsAll(prevRepos)) {
		    			JsonElement vulnsArrEl = rpoObj.get("confirmedVulns");
		    			if(vulnsArrEl !=null && !vulnsArrEl.isJsonNull() && vulnsArrEl.isJsonArray()) {
			    			JsonArray arr = vulnsArrEl.getAsJsonArray();
			    			JsonArray prevVulnsArray = gson.fromJson(arr, JsonArray.class);
			    			if(prevVulnsArray != null && !prevVulnsArray.isJsonNull()) {
			    				obj.add("prev", prevVulnsArray);
			    			}
		    			}
		    			return obj;
	    			}
	    		}
	    	}
    	}
    	return obj;
    }
    
    public String getImageNameOrImageId() {
    	return StringUtils.isNotBlank(this.imageNameInput) ? this.imageNameInput : dockerImageId;
    }
    
    public String getImageId() {
    	return dockerImageId;
    }
    
    public String getImageSummaryPortalURL() {
    	if (portalURL.endsWith("/")) {
    		return portalURL + "cs/#/assets/images/" + imageSHA;
    	}
    	else {
    		return portalURL + "/cs/#/assets/images/" + imageSHA;
    	}
    }
    
    @Override
    public String getIconFileName() {
        return "clipboard.png";
    }

    @Override
    public String getDisplayName() {
        return "Qualys Report For " + dockerImageId;
    }

    @Override
    public String getUrlName() {
        return "qualys_report_for_" + dockerImageId + ".html";
    }
}