package com.qualys.plugins.containerSecurity;

import java.io.IOException;
import java.io.PrintStream;
import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.qualys.plugins.common.QualysAuth.AuthType;
import com.qualys.plugins.containerSecurity.util.OAuthCredential;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.qualys.plugins.common.QualysAuth.QualysAuth;
import com.qualys.plugins.common.QualysClient.QualysCSClient;
import com.qualys.plugins.common.QualysClient.QualysCSTestConnectionResponse;
import com.qualys.plugins.containerSecurity.config.QualysGlobalConfig;
import com.qualys.plugins.containerSecurity.model.ProxyConfiguration;
import com.qualys.plugins.containerSecurity.util.Helper;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import qshaded.com.google.gson.Gson;
import qshaded.com.google.gson.JsonArray;
import qshaded.com.google.gson.JsonElement;
import qshaded.com.google.gson.JsonObject;
import qshaded.com.google.gson.reflect.TypeToken;

import static com.qualys.plugins.containerSecurity.util.Helper.buildMaskedLabel;
import static com.qualys.plugins.containerSecurity.util.Helper.safe;
import static org.apache.commons.lang.StringUtils.isNotBlank;

@Extension
public class GetImageVulnsNotifier extends Notifier implements SimpleBuildStep {
	private String apiServer;
	private String platform;
	private String apiUser;
    private Secret apiPass;
    private String credentialsId;
    private String imageIds;
    private String pollingInterval;
    private String vulnsTimeout;
    private boolean isFailOnSevereVulns;
    private int severity1Limit;
    private int severity2Limit;
    private int severity3Limit;
    private int severity4Limit;
    private int severity5Limit;
    private boolean isSev1Vulns = false;
    private boolean isSev2Vulns = false;
    private boolean isSev3Vulns = false;
    private boolean isSev4Vulns = false;
    private boolean isSev5Vulns = false;
    private String proxyServer;
    private Secret proxyPassword;
    private String proxyUsername;
    private int proxyPort;
    private String proxyCredentialsId;
    private boolean useProxy = false;
    
    private String excludeList;
    private String excludeBy;
    private boolean isExcludeConditions;

    private boolean isFailOnQidFound;
    private String qidList;
    
    private boolean isFailOnCVEs = false;
    private String cveList;
    
    private boolean isFailOnSoftware = false;
    private String softwareList;
    
    private boolean isPotentialVulnsToBeChecked = false;
	private boolean useLocalConfig = false;
	private boolean useGlobalConfig = false;
	
	private String webhookUrl;
	private String dockerUrl;
	private String dockerCert;
	
    private String cvssVersion;
    private String cvssThreshold;
    private boolean failByCvss = false;
	
	private JsonObject criteriaObj;
	private long taggingTime;
    
	
    private final static Logger logger = Logger.getLogger(GetImageVulnsNotifier.class.getName());
    private final static int DEFAULT_POLLING_INTERVAL_FOR_VULNS = 30; //in sec
    private final static int DEFAULT_TIMEOUT_FOR_VULNS = 600; //in sec

    @DataBoundConstructor
    public GetImageVulnsNotifier(boolean useGlobalConfig, boolean useLocalConfig, String apiServer, String apiUser, String apiPass, String credentialsId, String pollingInterval,
    		String vulnsTimeout, boolean isFailOnSevereVulns, int severity1Limit, int severity2Limit, int severity3Limit, int severity4Limit, int severity5Limit, boolean isSev1Vulns,
    		boolean isSev2Vulns, boolean isSev3Vulns, boolean isSev4Vulns, boolean isSev5Vulns, String proxyServer, int proxyPort, String proxyUsername,
    		String proxyPassword, boolean useProxy,  String proxyCredentialsId, boolean isFailOnQidFound, String qidList, boolean isFailOnCVEs, String cveList, boolean isFailOnSoftware, String softwareList, boolean isPotentialVulnsToBeChecked, String imageIds, String webhookUrl,
    		boolean isExcludeConditions, String excludeBy, String excludeList, boolean failByCvss, String cvssVersion, String cvssThreshold,String platform, String dockerUrl, String dockerCert) {
		
		if(useGlobalConfig) {
			this.imageIds = imageIds;
			this.useGlobalConfig = useGlobalConfig;
        }
        if(useLocalConfig) {
        	this.useLocalConfig = useLocalConfig;
        	this.imageIds = imageIds;
			this.apiServer = apiServer;
			this.platform = platform;
			if(apiUser!=null && !apiUser.isEmpty()) { this.apiUser = apiUser; }
        	if(apiPass!=null && !apiPass.isEmpty()) { this.apiPass = Secret.fromString(apiPass); }
        	this.credentialsId = credentialsId;
        	this.pollingInterval = pollingInterval;
        	this.vulnsTimeout = vulnsTimeout;
        	this.isFailOnSevereVulns = isFailOnSevereVulns;
        	this.isSev1Vulns = isSev1Vulns;
        	if(isSev1Vulns && severity1Limit > 0) { this.severity1Limit = severity1Limit; }
        	this.isSev2Vulns = isSev2Vulns;
        	if(isSev2Vulns && severity2Limit > 0) { this.severity2Limit = severity2Limit; }
        	this.isSev3Vulns = isSev3Vulns;
        	if(isSev3Vulns && severity3Limit > 0) { this.severity3Limit = severity3Limit; }
        	this.isSev4Vulns = isSev4Vulns;
        	if(isSev4Vulns && severity4Limit > 0) { this.severity4Limit = severity4Limit; }
        	this.isSev5Vulns = isSev5Vulns;
        	if(isSev5Vulns && severity5Limit > 0) { this.severity5Limit = severity5Limit; }
        	this.useProxy = useProxy;
        	if(useProxy) {
        		this.proxyCredentialsId = proxyCredentialsId;
        		if(proxyServer!=null && !proxyServer.isEmpty()) { this.proxyServer = proxyServer; }
        		this.proxyPort = proxyPort;
        		if(proxyUsername!=null && !proxyUsername.isEmpty()) { this.proxyUsername = proxyUsername; }
        		if(proxyPassword!=null && !proxyPassword.isEmpty()) { this.proxyPassword = Secret.fromString(proxyPassword); }
        	}
        	this.isFailOnQidFound = isFailOnQidFound;
        	if(isFailOnQidFound) {
        		if(qidList != null && !StringUtils.isBlank(qidList)) { this.qidList = qidList;}
        	}
        	
        	this.isFailOnCVEs = isFailOnCVEs;
        	if(isFailOnCVEs) {
        		if(cveList != null && !StringUtils.isBlank(cveList)) { this.cveList = cveList;}
        	}
        	this.isFailOnSoftware = isFailOnSoftware;
        	if(isFailOnSoftware) {
        		if(softwareList != null && !StringUtils.isBlank(softwareList)) { this.softwareList = softwareList;}
        	}
        	this.isExcludeConditions = isExcludeConditions;
        	if(isExcludeConditions) {
        		this.excludeBy = excludeBy;
        		this.excludeList = excludeList;
        	}
        	this.isPotentialVulnsToBeChecked = isPotentialVulnsToBeChecked;
        	
        	if(failByCvss) {
            	this.failByCvss = failByCvss;
            	this.cvssVersion = cvssVersion;
            	this.cvssThreshold = cvssThreshold;
            }
        }
        if(!StringUtils.isBlank(webhookUrl)) {
    		this.webhookUrl = webhookUrl;
    	}
		if(!StringUtils.isBlank(dockerUrl)) {
			this.dockerUrl = dockerUrl;
		}
		if(!StringUtils.isBlank(dockerCert)){
			this.dockerCert = dockerCert;
		}
    }

    public GetImageVulnsNotifier() { }
    
    public String getPlatform() {
        return platform;
    }
    
    @DataBoundSetter
    public void setPlatform(String platform) {
        this.platform = platform;
    }
    
    public String getApiUser() {return apiUser;}
    @DataBoundSetter
    public void setApiUser(String apiUser) {this.apiUser = apiUser;}
    
    public Secret getApiPass() { 
    	return apiPass;
    }
    @DataBoundSetter
    public void setApiPass(String apiPass) {this.apiPass = Secret.fromString(apiPass);}
    
    public String getProxyUsername() {return proxyUsername;}
	@DataBoundSetter
	public void setProxyUsername(String proxyUsername) {this.proxyUsername = proxyUsername;}
	
	public Secret getProxyPassword() {
		return proxyPassword;
	}
	@DataBoundSetter
	public void setProxyPassword(String proxyPassword) {this.proxyPassword = Secret.fromString(proxyPassword);}
    
    public boolean getFailByCvss() {return failByCvss;}
	@DataBoundSetter
	public void setFailByCvss(boolean failByCvss) {this.failByCvss = failByCvss;}
	
	public String getCvssVersion() {return cvssVersion;}
	@DataBoundSetter
	public void setCvssVersion(String cvssVersion) {this.cvssVersion = cvssVersion;}
	
	public String getCvssThreshold() {return cvssThreshold;}
	@DataBoundSetter
	public void setCvssThreshold(String cvssThreshold) {this.cvssThreshold = cvssThreshold;}
    
    @DataBoundSetter
	public void setSoftwareList(String list) {
		this.softwareList = list;
	}
	
	public boolean getIsFailOnSoftware() {
		return isFailOnSoftware;
	}

	@DataBoundSetter
	public void setIsFailOnSoftware(boolean software) {
		this.isFailOnSoftware = software;
	}

	public String getSoftwareList() {
		return softwareList;
	}
    
    public boolean getIsExcludeConditions() {
        return isExcludeConditions;
    }

	@DataBoundSetter
    public void setIsExcludeConditions(boolean isExcludeConditions) {
        this.isExcludeConditions = isExcludeConditions;
    }
    
    public String getExcludeBy() {
        return excludeBy;
    }

	@DataBoundSetter
    public void setExcludeBy(String excludeBy) {
        this.excludeBy = excludeBy;
    }
    
    public String getExcludeList() {
        return excludeList;
    }

	@DataBoundSetter
    public void setExcludeList(String excludeList) {
        this.excludeList = excludeList;
    }
    
    public String getWebhookUrl() {
        return webhookUrl;
    }

	@DataBoundSetter
    public void setWebhookUrl(String webhookUrl) {
        this.webhookUrl = webhookUrl;
    }
    
    @DataBoundSetter
    public void setPollingInterval(String pollingInterval) {
    	this.pollingInterval = pollingInterval;
    }

	@DataBoundSetter
	public void setVulnsTimeout(String vulnsTimeout) {
		this.vulnsTimeout = vulnsTimeout;
	}
	
	@DataBoundSetter
	public void setIsFailOnSevereVulns(boolean isFailOnSevereVulns) {
		this.isFailOnSevereVulns = isFailOnSevereVulns;
	}
	
	public boolean getIsFailOnQidFound() {
		return isFailOnQidFound;
	}

	@DataBoundSetter
	public void setIsFailOnQidFound(boolean isFailOnQidFound) {
		this.isFailOnQidFound = isFailOnQidFound;
	}

	public String getQidList() {
		return qidList;
	}

	@DataBoundSetter
	public void setQidList(String qidList) {
		this.qidList = qidList;
	}
	
	public boolean getIsFailOnCVEs() {
		return isFailOnCVEs;
	}

	@DataBoundSetter
	public void setIsFailOnCVEs(boolean CVEs) {
		this.isFailOnCVEs = CVEs;
	}

	public String getCveList() {
		return cveList;
	}

	@DataBoundSetter
	public void setCveList(String list) {
		this.cveList = list;
	}
	
	public boolean getIsPotentialVulnsToBeChecked() {
		return isPotentialVulnsToBeChecked;
	}

	@DataBoundSetter
	public void setIsPotentialVulnsToBeChecked(boolean isPotentialVulnsToBeChecked) {
		this.isPotentialVulnsToBeChecked = isPotentialVulnsToBeChecked;
	}
	    
	@DataBoundSetter
	public void setSeverity1Limit(int severity1Limit) {
		this.severity1Limit = severity1Limit;
	}
	
	public int getSeverity1Limit() {
		return severity1Limit;
	}

	@DataBoundSetter
	public void setSeverity2Limit(int severity2Limit) {
		this.severity2Limit = severity2Limit;
	}
	
	public int getSeverity2Limit() {
		return severity2Limit;
	}
	
	@DataBoundSetter
	public void setSeverity3Limit(int severity3Limit) {
		this.severity3Limit = severity3Limit;
	}
	
	public int getSeverity3Limit() {
		return severity3Limit;
	}
	
	@DataBoundSetter
	public void setSeverity4Limit(int severity4Limit) {
		this.severity4Limit = severity4Limit;
	}
	
	public int getSeverity4Limit() {
		return severity4Limit;
	}
	
	@DataBoundSetter
	public void setSeverity5Limit(int severity5Limit) {
		this.severity5Limit = severity5Limit;
	}
	
	public int getSeverity5Limit() {
		return severity5Limit;
	}
	
	@DataBoundSetter
	public void setIsSev1Vulns(boolean isSev1Vulns) {
		this.isSev1Vulns = isSev1Vulns;
	}

	public boolean getIsSev1Vulns() {
		return isSev1Vulns;
	}
	
	@DataBoundSetter
	public void setIsSev2Vulns(boolean isSev2Vulns) {
		this.isSev2Vulns = isSev2Vulns;
	}

	public boolean getIsSev2Vulns() {
		return isSev2Vulns;
	}
	
	@DataBoundSetter
	public void setIsSev3Vulns(boolean isSev3Vulns) {
		this.isSev3Vulns = isSev3Vulns;
	}

	public boolean getIsSev3Vulns() {
		return isSev3Vulns;
	}
	
	
	@DataBoundSetter
	public void setIsSev4Vulns(boolean isSev4Vulns) {
		this.isSev4Vulns = isSev4Vulns;
	}

	public boolean getIsSev4Vulns() {
		return isSev4Vulns;
	}
	
	@DataBoundSetter
	public void setIsSev5Vulns(boolean isSev5Vulns) {
		this.isSev5Vulns = isSev5Vulns;
	}

	public boolean getIsSev5Vulns() {
		return isSev5Vulns;
	}
	
	public boolean getIsFailOnSevereVulns() {
		return isFailOnSevereVulns;
	}

	public String getPollingInterval() {
    	return pollingInterval;
	}
	 
	public String getVulnsTimeout() {
		return vulnsTimeout;
	}

	public String getApiServer() {
        return apiServer;
    }
	
	@DataBoundSetter
	public void setApiServer(String apiServer) {
        this.apiServer = apiServer.trim();
    }

    public String getCredentialsId() {
        return credentialsId;
    }
    
    @DataBoundSetter
	public void setCredentialsId(String credentialsId) {
        this.credentialsId = credentialsId;
    }
    
    public String getProxyServer() {
		return proxyServer;
	}

	@DataBoundSetter
	public void setProxyServer(String proxyServer) {
		this.proxyServer = proxyServer;
	}
	
	public int getProxyPort() {
		return proxyPort;
	}

	@DataBoundSetter
	public void setProxyPort(int proxyPort) {
		this.proxyPort = proxyPort;
	}
	
	public String getProxyCredentialsId() {
		return proxyCredentialsId;
	}

	@DataBoundSetter
	public void setProxyCredentialsId(String proxyCredentialsId) {
		this.proxyCredentialsId = proxyCredentialsId;
	}
	
	public boolean getUseProxy() {
		return useProxy;
	}

	@DataBoundSetter
	public void setUseProxy(boolean useProxy) {
		this.useProxy = useProxy;
	}
	
	@DataBoundSetter
	public void setImageIds(String images) {
		this.imageIds = images;
	}
    
    public String getImageIds() {
    	return imageIds;
    }

	@DataBoundSetter
	public void setDockerUrl(String dockerUrl) {
		this.dockerUrl = dockerUrl;
	}

	public String getDockerUrl() {
		return dockerUrl;
	}

	@DataBoundSetter
	public void setDockerCert(String dockerCert) {
		this.dockerCert = dockerCert;
	}

	public String getDockerCert() {
		return dockerCert;
	}
    
    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }
    
    @DataBoundSetter
    public void setUseLocalConfig(boolean useLocalConfig) {
		this.useLocalConfig = useLocalConfig;
		
	}
    
    @DataBoundSetter
	public void setUseGlobalConfig(boolean useGlobalConfig) {
		this.useGlobalConfig = useGlobalConfig;
		
	}
	
	public boolean getUseLocalConfig() {
		return useLocalConfig;
		
	}

	public boolean getUseGlobalConfig() {
		return useGlobalConfig;
		
	}
	
	public String getPluginVersion() throws IOException {
		String path = GetImageVulnsNotifier.class.getProtectionDomain().getCodeSource().getLocation().getPath();
		String versionName = path.split("qualys-cs_")[1];
		String version = versionName.substring(0, versionName.length() - 4);
        return version;
	}

    @Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath filePath, @Nonnull Launcher launcher, @Nonnull TaskListener taskListener) throws InterruptedException, IOException {
    	logger.info("Triggered build #" + run.number);
    	try {
    		String version = getPluginVersion();
    		taskListener.getLogger().println("Qualys Container Scanning Connector(version-" + version + ") started.");
    	}catch(Exception e) {
    		taskListener.getLogger().println("Qualys Container Scanning Connector started.");
    		logger.info("Could not read version from pom.xml. Reason: " + e.getMessage());
    	}
    	try {
			setConfigOptions(taskListener, run);
			this.criteriaObj = getCriteriaAsJsonObject();
		} catch (AbortException e2) {
			throw e2;
		}
   
        String imageIdCSV = null;
 		try {
 			imageIdCSV = getDockerImageId(run.getEnvironment(taskListener), taskListener.getLogger());
 		} catch (Exception e1) {
 			taskListener.getLogger().println("Exception while reading environment variable IMAGE_ID: " + e1.getMessage());
 		}
       
        
     	if (imageIds != null && !imageIds.isEmpty()) {
         	String[] imageList = imageIds.split(",");
              try {
             	 Item project = run.getParent();
             	getImageScanResult(run, taskListener,  new ArrayList<String>(Arrays.asList(imageList)), project, filePath.absolutize(), launcher);
              } catch(QualysEvaluationException exc) {
             	 throw new AbortException(exc.getMessage());
              } catch (Exception e) {
             	 throw new AbortException(e.getMessage());
              }
        } else if (isNotBlank(imageIdCSV)) {  //for freestyle, we may need to read from env var
        	 taskListener.getLogger().println("IMAGE_ID read from EnvVars is " + imageIdCSV);
     		String[] imageList = imageIdCSV.split(",");
     		try {
     			Item project = run.getParent();
     			getImageScanResult(run, taskListener,  new ArrayList<String>(Arrays.asList(imageList)), project, filePath.absolutize(), launcher);
     		} catch(QualysEvaluationException exc) {
            	 	throw new AbortException(exc.getMessage());
             } catch (Exception e) {
                 //taskListener.getLogger().println("Exception in Qualys Vulnerabilities scan result: " + e.getMessage());
             	throw new AbortException(e.getMessage());
             }
     	} else {
     		taskListener.getLogger().println("No image ids found!");
     		throw new AbortException("Image IDs can't be set to null or empty.");
     	}
         
        return;
    }
    
    public void setConfigOptions(TaskListener listener, Run<?, ?> run) throws AbortException {
    	if(useGlobalConfig) {
    		this.apiServer = QualysGlobalConfig.get().getApiServer();
    		this.apiServer = apiServer.trim();
    		//setting credentials from credentials store
    		credentialsId = QualysGlobalConfig.get().getCredentialsId();
    		
    		if (StringUtils.isEmpty(credentialsId) && StringUtils.isEmpty(apiServer)) {
        		throw new AbortException("This Job is configured to use Global Configuration but Qualys Credentials/API Server fields are set to empty in Global configuration!");
            }
    		this.useProxy = QualysGlobalConfig.get().getUseProxy();
    		this.pollingInterval = QualysGlobalConfig.get().getPollingInterval();
    		this.vulnsTimeout = QualysGlobalConfig.get().getVulnsTimeout();
    		//this.isFailOnSevereVulns = QualysGlobalConfig.get().getIsFailOnSevereVulns();
    		this.severity1Limit = QualysGlobalConfig.get().getSeverity1Limit();
    		this.severity2Limit = QualysGlobalConfig.get().getSeverity2Limit();
    		this.severity3Limit = QualysGlobalConfig.get().getSeverity3Limit();
    		this.severity4Limit = QualysGlobalConfig.get().getSeverity4Limit();
    		this.severity5Limit = QualysGlobalConfig.get().getSeverity5Limit();
    		this.isSev1Vulns = QualysGlobalConfig.get().getIsSev1Vulns();
    		this.isSev2Vulns = QualysGlobalConfig.get().getIsSev2Vulns();
    		this.isSev3Vulns = QualysGlobalConfig.get().getIsSev3Vulns();
    		this.isSev4Vulns = QualysGlobalConfig.get().getIsSev4Vulns();
    		this.isSev5Vulns = QualysGlobalConfig.get().getIsSev5Vulns();
    		this.proxyServer = QualysGlobalConfig.get().getProxyServer();
    		this.proxyPort = QualysGlobalConfig.get().getProxyPort();
    		this.proxyCredentialsId = QualysGlobalConfig.get().getProxyCredentialsId();
    		this.proxyPassword = QualysGlobalConfig.get().getProxyPassword();
    		this.proxyUsername = QualysGlobalConfig.get().getProxyUsername();
    		this.isFailOnQidFound = QualysGlobalConfig.get().getIsFailOnQidFound();
    		this.qidList = QualysGlobalConfig.get().getQidList();
    		this.isFailOnCVEs = QualysGlobalConfig.get().getIsFailOnCVEs();
    		this.cveList = QualysGlobalConfig.get().getCveList();
    		this.isFailOnSoftware = QualysGlobalConfig.get().getIsFailOnSoftware();
    		this.softwareList = QualysGlobalConfig.get().getSoftwareList();
    		this.isPotentialVulnsToBeChecked = QualysGlobalConfig.get().getIsPotentialVulnsToBeChecked();
    		
    		this.isExcludeConditions = QualysGlobalConfig.get().getIsExcludeConditions();
    		this.excludeBy = QualysGlobalConfig.get().getExcludeBy();
    		this.excludeList = QualysGlobalConfig.get().getExcludeList();
    		this.failByCvss = QualysGlobalConfig.get().getFailByCvss();
    		this.cvssVersion = QualysGlobalConfig.get().getCvssVersion();
    		this.cvssThreshold = QualysGlobalConfig.get().getCvssThreshold();
    				
    		JsonObject json = configToJson();
    		listener.getLogger().println("Using Global configuration settings for Qualys Container Security step : " + json.toString());
    		logger.info("Using Global configuration settings for Qualys Container Security step : " + json.toString());
    		
    	}else {
    		JsonObject json = configToJson();
    		listener.getLogger().println("Using Job Specific configuration settings for Qualys Container Security step : " + json.toString());
    		logger.info("Using Job Specific configuration settings for Qualys Container Security step  : " + json.toString());
    	}
    	
    	this.isFailOnSevereVulns = this.isSev1Vulns || this.isSev2Vulns || this.isSev3Vulns || this.isSev4Vulns || this.isSev5Vulns;
    	
    	if(this.webhookUrl != null && !StringUtils.isBlank(this.webhookUrl)) {
			logger.info("Using Job Specific Webhook URL settings : " + this.webhookUrl);
			listener.getLogger().println("Using Job Specific Webhook URL settings : " + this.webhookUrl);
		} else {
			String url = QualysGlobalConfig.get().getWebhookUrl();
    		if(url != null && !StringUtils.isBlank(url)) {
    			this.webhookUrl = url;
    			logger.info("Using Global Webhook URL settings : " + this.webhookUrl);
    			listener.getLogger().println("Using Global Webhook URL settings : " + this.webhookUrl);
    		}else {
				logger.info("No webhook configured.");
				listener.getLogger().println("No webhook configured.");
			}
		}

		if(this.dockerUrl != null && !StringUtils.isBlank(this.dockerUrl)) {
			logger.info("Using Job Specific Docker Url/Nerdctl binary path settings : " + this.dockerUrl);
			listener.getLogger().println("Using Job Specific Docker Url/Nerdctl binary path settings : " + this.dockerUrl);
			if(this.dockerCert != null && !StringUtils.isBlank(this.dockerCert)) {
				logger.info("Using Job Specific Docker cert settings : " + this.dockerCert);
				listener.getLogger().println("Using Job Specific Docker cert settings : " + this.dockerCert);
			}
		} else {
			String dockerUrlConf = QualysGlobalConfig.get().getDockerUrl();
			if (StringUtils.isEmpty(dockerUrlConf)) {
				this.dockerUrl = "unix:///var/run/docker.sock";
			} else {
				this.dockerUrl = dockerUrlConf;
				logger.info("Using Global Docker Url/Nerdctl binary path settings : " + this.dockerUrl);
				listener.getLogger().println("Using Global Docker Url/Nerdctl binary path settings : " + this.dockerUrl);
			}
			String dockerCertConf = QualysGlobalConfig.get().getDockerCert();
			if(!StringUtils.isEmpty(dockerCertConf)) {
				this.dockerCert = dockerCertConf;
				if(this.dockerCert != null && !StringUtils.isBlank(this.dockerCert)) {
					logger.info("Using Global Docker Cert settings : " + this.dockerCert);
					listener.getLogger().println("Using Global Docker Cert settings : " + this.dockerCert);
				}

			}
		}
    	
    	
    }
    
    public JsonObject getCriteriaAsJsonObject() {
    	JsonObject obj = new JsonObject();
    	obj.addProperty("webhookUrl", this.webhookUrl);
		obj.addProperty("dockerUrl", this.dockerUrl);
		obj.addProperty("dockerCert", this.dockerCert);
    	
    	JsonObject dataCollectionObj = new JsonObject();
    	dataCollectionObj.addProperty("frequency", this.pollingInterval);
    	dataCollectionObj.addProperty("timeout", this.vulnsTimeout);
    	obj.add("dataCollection", dataCollectionObj);

    	JsonObject failConditionsObj = new JsonObject();
    	Gson gson = new Gson();
    	if(isFailOnQidFound) {
	    	if(this.qidList == null || this.qidList.isEmpty()) {
	    		JsonElement empty = new JsonArray();
	    		failConditionsObj.add("qids", empty);
	    	}else {
		    	List<String> qids = Arrays.asList(this.qidList.split(","));
		    	JsonElement element = gson.toJsonTree(qids, TypeToken.getParameterized(List.class, String.class).getType()); 
		    	failConditionsObj.add("qids", element);
	    	}
    	}
    	if(this.isFailOnCVEs) {
	    	if(this.cveList == null || this.cveList.isEmpty()) {
	    		JsonElement empty = new JsonArray();
	    		failConditionsObj.add("cves", empty);
	    	}else {
		    	List<String> cves = Arrays.asList(this.cveList.split(","));
		    	JsonElement element2 = gson.toJsonTree(cves, TypeToken.getParameterized(List.class, String.class).getType()); 
		    	failConditionsObj.add("cves", element2);
	    	}
    	}		
    	if(this.failByCvss) {    		
    		if((this.cvssThreshold == null || this.cvssThreshold.isEmpty()) && (this.cvssVersion == null || this.cvssVersion.isEmpty())) {
    			JsonElement empty = new JsonArray();
    			failConditionsObj.add("version", empty);
    			failConditionsObj.add("configured", empty);
    		}else {
    			JsonObject cvssObj = new JsonObject();
        		cvssObj.addProperty("version", this.cvssVersion);
        		cvssObj.addProperty("configured", Double.parseDouble(this.cvssThreshold));            	
    			failConditionsObj.add("cvss", cvssObj);    			
    		}
    	}
    	
    	JsonElement empty = new JsonArray();
		failConditionsObj.add("software", empty);
    	if(this.isFailOnSoftware) {
	    	if(this.softwareList != null && !this.softwareList.isEmpty()) {
	    		List<String> softwares = Arrays.asList(this.softwareList.split(","));
	    		softwares.replaceAll(String::trim);
		    	JsonElement element2 = gson.toJsonTree(softwares, TypeToken.getParameterized(List.class, String.class).getType()); 
		    	failConditionsObj.add("software", element2);
	    	}
    	}
    	
    	JsonObject severities = new JsonObject();
    	if(this.isSev5Vulns) severities.addProperty("5", this.severity5Limit);
    	if(this.isSev4Vulns) severities.addProperty("4", this.severity4Limit);
    	if(this.isSev3Vulns) severities.addProperty("3", this.severity3Limit);
    	if(this.isSev2Vulns) severities.addProperty("2", this.severity2Limit);
    	if(this.isSev1Vulns) severities.addProperty("1", this.severity1Limit);
    	failConditionsObj.add("severities", severities);
    	if(isExcludeConditions) {
    		if("cve".equals(excludeBy)) {
    			failConditionsObj.addProperty("excludeBy", "cve");
    			List<String> cves = Arrays.asList(this.excludeList.split(","));
    	    	JsonElement element = gson.toJsonTree(cves, TypeToken.getParameterized(List.class, String.class).getType()); 
    	    	failConditionsObj.add("excludeCVEs", element);
    		}
    		if("qid".equals(excludeBy)) {
    			failConditionsObj.addProperty("excludeBy", "qid");
    			List<String> qids = Arrays.asList(this.excludeList.split(","));
    	    	JsonElement element = gson.toJsonTree(qids, TypeToken.getParameterized(List.class, String.class).getType()); 
    	    	failConditionsObj.add("excludeQids", element);
    		}
    	}
    	failConditionsObj.addProperty("checkPotentialVulns", this.isPotentialVulnsToBeChecked);
    	obj.add("failConditions",failConditionsObj);
    	
    	logger.info("Criteria Object to common library: " + obj);
    	return obj;
    }
    
    public JsonObject configToJson() {
    	JsonObject obj = new JsonObject();
		if(!Objects.isNull(this.apiServer) && !StringUtils.isBlank(this.apiServer)) obj.addProperty("apiServer", this.apiServer);
		if(!Objects.isNull(this.platform) && !StringUtils.isBlank(this.platform))   obj.addProperty("platform", this.platform);
		if (!Objects.isNull(this.platform) && !this.platform.equalsIgnoreCase("pcp") && Helper.platformsList.containsKey(this.platform)) {
			Map<String, String> platformObj = Helper.platformsList.get(this.platform);
			obj.addProperty("apiServer", platformObj.get("url"));
			this.apiServer = platformObj.get("url");
		}
		obj.addProperty("useProxy", this.useProxy);
		if(this.proxyServer != null && this.useProxy && !StringUtils.isBlank(this.proxyServer)) obj.addProperty("proxyServer", this.proxyServer);
		if(this.useProxy) obj.addProperty("proxyPort", this.proxyPort);
		if(this.proxyCredentialsId != null && this.useProxy && !StringUtils.isBlank(this.proxyCredentialsId)) obj.addProperty("proxyCredentialsId", this.proxyCredentialsId);
		obj.addProperty("pollingInterval", this.pollingInterval);
		obj.addProperty("vulnsTimeout", this.vulnsTimeout);
		//obj.addProperty("isFailOnSevereVulns", this.isFailOnSevereVulns);
		if(this.isSev1Vulns) {
			obj.addProperty("isSev1Vulns", this.isSev1Vulns);
			obj.addProperty("severity1Limit", this.severity1Limit);
		}
		if(this.isSev2Vulns) {
			obj.addProperty("isSev2Vulns", this.isSev2Vulns);
			obj.addProperty("severity2Limit", this.severity2Limit);
		}
		if(this.isSev3Vulns) {
			obj.addProperty("isSev3Vulns", this.isSev3Vulns);
			obj.addProperty("severity3Limit", this.severity3Limit);
		}
		if(this.isSev4Vulns) {
			obj.addProperty("isSev4Vulns", this.isSev4Vulns);
			obj.addProperty("severity4Limit", this.severity4Limit);
		}
		if(this.isSev5Vulns) {
			obj.addProperty("isSev5Vulns", this.isSev5Vulns);
			obj.addProperty("severity5Limit", this.severity5Limit);
		}
		obj.addProperty("isExcludeConditions", this.isExcludeConditions);
		if(this.isExcludeConditions) {
			obj.addProperty("excludeBy", this.excludeBy);
			if("qid".equals(this.excludeBy)) {
				obj.addProperty("QidExcludeList", this.excludeList);
			}
			if("cve".equals(this.excludeBy)) {
				obj.addProperty("CveExcludeList", this.excludeList);
			}
		}		
		if(this.failByCvss) {
			obj.addProperty("failByCvss", this.failByCvss);
			obj.addProperty("cvssVersion", this.cvssVersion);
			obj.addProperty("cvssThreshold", Double.parseDouble(this.cvssThreshold));			
		}
		
		obj.addProperty("isFailOnQidFound", this.isFailOnQidFound);
		if(this.isFailOnQidFound) obj.addProperty("qidList", this.qidList);
		
		obj.addProperty("isFailOnCVEs", this.isFailOnCVEs);
		if(this.isFailOnCVEs) obj.addProperty("cveList", this.cveList);
		
		obj.addProperty("isFailOnSoftware", this.isFailOnSoftware);
		if(this.isFailOnSoftware) {
			if(this.softwareList != null && !this.softwareList.isEmpty()) {
	    		List<String> softwares = Arrays.asList(this.softwareList.split(","));
	    		softwares.replaceAll(String::trim);
	    		obj.addProperty("softwareList", String.join(", ", softwares));
			}else {
				obj.addProperty("softwareList", this.softwareList);
			}
		}
		
		obj.addProperty("isPotentialVulnsToBeChecked", this.isPotentialVulnsToBeChecked);
    	return obj;
    }
    
    /*
     *  Get the list of docker image ids and get scan results for them through client
     */
    public void getImageScanResult(Run<?, ?> run, TaskListener listener, ArrayList<String> imageList, Item project, FilePath workspace, Launcher launcher) throws Exception {
    	if (imageList == null || imageList.isEmpty()) {
		 	listener.getLogger().println("No image ids found.");
		if (isFailOnSevereVulns || isFailOnQidFound || isFailOnCVEs || isFailOnSoftware || failByCvss) {
			throw new Exception("No image ids found");
		 	} else {
		 		return;
		 	}
		 }
		 
		 //tagging images with qualys container security tag
		 //tagImages(imageIdList, listener, launcher);
		 Set<String> imageSet = new LinkedHashSet<>(imageList);
		 
	     HashMap<String, String> uniqueImageIdList = processImages(imageSet, listener, launcher);
        QualysAuth auth = new QualysAuth();
		String apiUserVal = "";
    	String apiPassVal = "";
    	if(!StringUtils.isBlank(apiUser)) {
    		apiUserVal = apiUser;
    		apiPassVal = apiPass.getPlainText();
    	}
    	else{
    		try {
        		logger.info("Using qualys API Server URL: " + apiServer);
                StandardCredentials credentials = CredentialsMatchers.firstOrNull(
						CredentialsProvider.lookupCredentials(
                                StandardCredentials.class,
								project, ACL.SYSTEM,
								URIRequirementBuilder.fromUri(apiServer).build()),
						CredentialsMatchers.withId(credentialsId));
                if (credentials != null) {
                    if (credentials instanceof StandardUsernamePasswordCredentials) {
                        StandardUsernamePasswordCredentials userPass = (StandardUsernamePasswordCredentials) credentials;
                        apiUserVal = userPass.getUsername();
                        apiPassVal = userPass.getPassword().getPlainText();
                        auth.setQualysCredentials(apiServer, AuthType.Basic, apiUserVal, apiPassVal,"","");
                        if (apiPassVal.trim().equals("") || apiUserVal.trim().equals("")) {
                            throw new Exception("Username and/or Password field is empty for credentials id: " + credentialsId);
                        }
                    } else if (credentials instanceof OAuthCredential) {
                        OAuthCredential oauth = (OAuthCredential) credentials;
                        String clientId = oauth.getClientId();
                        String clientSecret = oauth.getClientSecret();
                        auth.setQualysCredentials(apiServer,AuthType.OAuth,"","",clientId,clientSecret);
                    } else
                        throw new IllegalArgumentException("Unsupported credential type: " + credentials.getClass());
                } else
					throw new Exception("Could not read credentials for API login : credentials id: " + credentialsId);
			}catch(Exception e){
				e.printStackTrace();
				//buildLogger.println("Invalid credentials! " + e.getMessage());
				throw new Exception("Invalid credentials! " + e.getMessage());
			}
    	}
    	String proxyUsernameVal = "";
		String proxyPasswordVal = "";
    	//test connection first

    	 Pattern pattern = Pattern.compile("\\{env.(.*?)\\}");
		 Matcher matcher = pattern.matcher(apiUserVal);
		 if (matcher.find())
		 {
			 try {
				apiUserVal = run.getEnvironment(listener).get(matcher.group(1));
			} catch (Exception e) {
				e.printStackTrace();
			}
			 listener.getLogger().println("Environment variable = " + matcher.group(1) + ", value = "+ apiUserVal);
		 }
		 
		 matcher = pattern.matcher(apiPassVal);
		 if (matcher.find())
		 {
			 try {
				 apiPassVal = run.getEnvironment(listener).get(matcher.group(1));
			} catch (Exception e) {
				e.printStackTrace();
			}
			 listener.getLogger().println("Environment variable = " + matcher.group(1) + ", value = "+ apiPassVal);
		 }
    	
    	if(useProxy) {
            if (isNotBlank(proxyUsername) && proxyPassword != null) {
    			proxyPasswordVal = proxyPassword.getPlainText();
    			proxyUsernameVal = proxyUsername;
    		}
    		if (StringUtils.isNotEmpty(proxyCredentialsId)) {
    			StandardUsernamePasswordCredentials credential = CredentialsMatchers.firstOrNull(
    					CredentialsProvider.lookupCredentials(
    							StandardUsernamePasswordCredentials.class,
    							project, ACL.SYSTEM,
    							URIRequirementBuilder.fromUri(apiServer).build()),
    					CredentialsMatchers.withId(proxyCredentialsId));
    			
    			if (credential != null) {
    				proxyUsernameVal = credential.getUsername();
                    proxyPasswordVal = credential.getPassword().getPlainText();
    			}
            }
        	auth.setProxyCredentials(proxyServer, proxyUsernameVal, proxyPasswordVal, proxyPort);
    	}
    	 
		int pollingIntervalForVulns = setTimeoutInSec("polling", DEFAULT_POLLING_INTERVAL_FOR_VULNS, pollingInterval, listener);
		int timeoutToFetchVulnsInMillis = setTimeoutInSec("vulns", DEFAULT_TIMEOUT_FOR_VULNS, vulnsTimeout, listener);
    	QualysCSClient client = new QualysCSClient(auth, listener.getLogger());
    	
    	boolean isFailConditionsConfigured = false;
    	if(isFailOnCVEs || isFailOnQidFound || isFailOnSevereVulns || isFailOnSoftware || failByCvss) {
    		isFailConditionsConfigured = true;
    	}
    	ProxyConfiguration proxyConfiguration = new ProxyConfiguration(useProxy, proxyServer, proxyPort, proxyUsernameVal, proxyPasswordVal); 
    	GetImageVulns executor = new GetImageVulns(client, auth, run, listener, pollingIntervalForVulns, timeoutToFetchVulnsInMillis, webhookUrl, criteriaObj, isFailConditionsConfigured, proxyConfiguration);
    	
    	listener.getLogger().println("Qualys task - Started fetching image scan results.");
        
    	executor.getAndProcessDockerImagesScanResult(uniqueImageIdList, taggingTime);
        listener.getLogger().println("Qualys task - Finished.");
    }
    
    private HashMap<String, String> processImages(Set<String> imageList, TaskListener listener, Launcher launcher) throws IOException, InterruptedException {
    	HashMap<String, String> finalImagesList = new HashMap<String, String>(); 
    	ArrayList<String> listOfImageIds = new ArrayList<String>();

        listener.getLogger().println("Checking if Qualys CS sensor is running on same instance using: " + dockerUrl + (isNotBlank(dockerCert) ? " & docker Cert path : " + dockerCert + "." : ""));
		//Check if sensor is running on same instance where images are built and docker daemon is shared
		
		VirtualChannel channel = launcher.getChannel();
	    Boolean isCICDSensorRunning =  (channel == null ? null : channel.call(new CheckSensorSlaveCallable(dockerUrl, dockerCert, listener)));
		
	    if (isCICDSensorRunning == null) {
	    	throw new AbortException("Unable to launch the sensor check operation using SlaveCallable");
	    }
		
		listener.getLogger().println("*** Qualys CS sensor container is up and running!! ***");
		
		if(!isCICDSensorRunning) {
			throw new AbortException("Qualys CS sensor is not deployed in CICD mode");
		}else {
			listener.getLogger().println("*** Qualys CS sensor is deployed in CICD mode ***");
		}

        listener.getLogger().println("For Image tagging, using " + (Helper.isRuntimeDocker(dockerUrl) ? "docker url: " : "Nerdctl binary path") + dockerUrl + (isNotBlank(dockerCert) ? " & docker Cert path : " + dockerCert + "." : ""));
		
		Instant instant = Instant.now();
		taggingTime = instant.getEpochSecond();
		listener.getLogger().println("***Epoch Time in seconds before tagging = " + taggingTime);
		
		for (String OriginalImage : imageList) {
    		String image = OriginalImage.trim();
    		String imageSha;
    		
    		try {
  				VirtualChannel channel2 = launcher.getChannel();
  				imageSha =  (channel2 == null ? null : channel2.call(new ImageShaExtractSlaveCallable(image, dockerUrl, dockerCert, listener)));
  			}catch(Exception e) {
  				e.printStackTrace(listener.getLogger());
  				throw e;
  			}
      		
    		if (imageSha != null) {
    			if (!listOfImageIds.contains(imageSha)) {
    				listOfImageIds.add(imageSha);
    				finalImagesList.put(imageSha, image);
    				logger.info("Adding qualys_scan_target tag to the image " + image);
    				listener.getLogger().println("Adding qualys specific tag to the image " + image);
    				try {
    					VirtualChannel channel2 = launcher.getChannel();
          				if (channel2 != null) {
          					channel2.call(new TagImageSlaveCallable(image, imageSha, dockerUrl, dockerCert, listener));
          				}
    				}catch(Exception e) {
    					e.printStackTrace(listener.getLogger());
    					throw e;
    				}
    			} else {
    				listener.getLogger().println(image + " has same image Id as one of the configured image: " + finalImagesList.get(imageSha) + ". So processing it only once.");
    			}
    			
    		}
    	}
    	return finalImagesList;
	}
    
    private int setTimeoutInSec(String timeoutType, int defaultTimeoutInSec, String timeout, TaskListener listener) {
    	int timeoutInSec = defaultTimeoutInSec;
    	if (!(timeout == null || timeout.isEmpty()) ){
    		try {
    			//if timeout is a regex of form 2*60*60 seconds, calculate the timeout in seconds
    			String[] numbers = timeout.split("\\*");
    			int timeoutInSecs =1;
    			for (int i = 0; i<numbers.length ; ++i) {
    				timeoutInSecs *= Long.parseLong(numbers[i]);
    			}
    			if(timeoutType.equals("polling") && timeoutInSecs < 30) {
    				listener.getLogger().println("Polling interval timeout cannot be less than 30 seconds. Using default polling interval of " + defaultTimeoutInSec + " seconds.");
    				return defaultTimeoutInSec;
    			}
    			return timeoutInSecs;
    		} catch(Exception e) {
    			listener.getLogger().println("Invalid " + timeoutType + " time value. Cannot parse -"+e.getMessage());
    			listener.getLogger().println("Using default period of " + defaultTimeoutInSec
    			+ " seconds for " + timeoutType + " data");
    		}
    	}
    	return timeoutInSec; 
    }
    
    private String getDockerImageId(EnvVars envVars, PrintStream logger) {
        String imageId = "";

        try {
           if (envVars == null || envVars.isEmpty()){
        	   return imageId;
           }
            imageId = envVars.get("IMAGE_ID", "");
        } catch (Exception e) {
            logger.println(e.getMessage());
        } 
         return imageId;
    }

   

	@Extension
	@Symbol(value = { "getImageVulnsFromQualys" })
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

        private final static String URL_REGEX = "^(https?)://[-a-zA-Z0-9+&#/%?=~_|!:,.;]*[-a-zA-Z0-9+&#/%=~_|]";
        private final static String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&#/%?=~_|!,.;]*[-a-zA-Z0-9+&#/%=~_|]";
        private final static String TIMEOUT_PERIOD_REGEX = "^(\\d+[*]?)*(?<!\\*)$";

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Scan container images with Qualys CS";
        }
        
        public FormValidation doCheckCveList(@QueryParameter String cveList) {
        	if(! Helper.isValidCVEList(cveList)) {
        		return FormValidation.error("Enter valid CVEs!");
        	}
        	return FormValidation.ok();
        }
        

        public FormValidation doCheckApiServer(@QueryParameter String apiServer) {
            try {
            	Pattern patt = Pattern.compile(URL_REGEX);
                Matcher matcher = patt.matcher(apiServer.trim());
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Server name is not valid!");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckWebhookUrl(@QueryParameter String webhookUrl) {
            try {
            	if(StringUtils.isEmpty(webhookUrl)) {
            		return FormValidation.ok();
            	}
            	Pattern patt = Pattern.compile(URL_REGEX);
                Matcher matcher = patt.matcher(webhookUrl);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Webhook Url is not valid!");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckCvssThreshold(@QueryParameter String cvssThreshold) {
        	try {
        		if (cvssThreshold != null && !cvssThreshold.isEmpty()) {        			
        			double cvssDouble = 0.0;
        			try {
        				cvssDouble = Double.parseDouble(cvssThreshold);
        				if(cvssDouble < 0.0 || cvssDouble > 10.0) {
            				return FormValidation.error("Please enter a number in range of 0.0 to 10.0");
            			}
    				} catch (NumberFormatException e) {
    					return FormValidation.error("Input is not a valid number. " + e.getMessage());        				    
    				}        			
        		}
        	} catch (RuntimeException e) {
        		return FormValidation.error("Enter valid number!");
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();        	
        } // End of doCheckCvssThreshold FormValidation

        public FormValidation doCheckApiUser(@QueryParameter String apiUser) {
            try {
                if (apiUser.trim().equals("")) {
                    return FormValidation.error("API Username cannot be empty.");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }

        public FormValidation doCheckApiPass(@QueryParameter String apiPass) {
            try {
                if (apiPass.trim().equals("")) {
                    return FormValidation.error("API Password cannot be empty.");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckPollingInterval(@QueryParameter String pollingInterval) {
            try {
            	 if (pollingInterval.trim().equals("")) {
             	    return FormValidation.ok();
            	 }
            	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
                 Matcher matcher = patt.matcher(pollingInterval);
             	
                 if (!(matcher.matches())) {
                     return FormValidation.error("Timeout period is not valid!");
                 } else {
                     //check if it is less than 30
                	 try {
             			//if timeout is a regex of form 2*60*60 seconds, calculate the timeout in seconds
             			String[] numbers = pollingInterval.split("\\*");
             			long timeoutInSecs =1;
             			for (int i = 0; i<numbers.length ; ++i) {
             				timeoutInSecs *= Long.parseLong(numbers[i]);
             			}
             			if(timeoutInSecs < 30) {
             				return FormValidation.error("Polling Interval Should not be less than 30 seconds");
             			}
             		} catch(Exception e) {
             			return FormValidation.error("Please enter valid Polling Interval");
             		}
                	 return FormValidation.ok();
                 }
            } catch (Exception e) {
            	return FormValidation.error("Timeout period string : " + pollingInterval + ", reason = " + e);
            }
        }

        public FormValidation doCheckVulnsTimeout(@QueryParameter String vulnsTimeout) {
            try {
            	 if (vulnsTimeout.trim().equals("")) {
             	    return FormValidation.ok();
            	 }
            	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
                 Matcher matcher = patt.matcher(vulnsTimeout);
             	
                 if (!(matcher.matches())) {
                     return FormValidation.error("Timeout period is not valid!");
                 } else {
                     return FormValidation.ok();
                 }
            } catch (Exception e) {
            	return FormValidation.error("Timeout period string : " + vulnsTimeout + ", reason = " + e);
            }
        }
        
        public FormValidation doCheckSeverity1Limit(@QueryParameter String severity1Limit) {
        	try {
        		if (severity1Limit != null && !severity1Limit.isEmpty()) {
        			int severity1LimitInt = Integer.parseInt(severity1Limit);
        			if(severity1LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity2Limit(@QueryParameter String severity2Limit) {
        	try {
        		if (severity2Limit != null && !severity2Limit.isEmpty()) {
        			int severity2LimitInt = Integer.parseInt(severity2Limit);
        			if(severity2LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity3Limit(@QueryParameter String severity3Limit) {
        	try {
        		if (severity3Limit != null && !severity3Limit.isEmpty()) {
        			int severity3LimitInt = Integer.parseInt(severity3Limit);
        			if(severity3LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity4Limit(@QueryParameter String severity4Limit) {
        	try {
        		if (severity4Limit != null && !severity4Limit.isEmpty()) {
        			int severity4LimitInt = Integer.parseInt(severity4Limit);
        			if(severity4LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity5Limit(@QueryParameter String severity5Limit) {
        	try {
        		if (severity5Limit != null && !severity5Limit.isEmpty()) {
        			int severity5LimitInt = Integer.parseInt(severity5Limit);
        			if(severity5LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckQidList(@QueryParameter String qidList) {
        	if (qidList == null || qidList.isEmpty()) {
        		return FormValidation.ok();
        	}
        	try {
        		String[] qidsString = qidList.split(",");
        		for (String qid : qidsString) {
        			if (qid.contains("-")) {
        				String[] range = qid.split("-");
        				int firstInRange = Integer.parseInt(range[0]);
        				int lastInRange = Integer.parseInt(range[1]);
        				
        				if (firstInRange > lastInRange) {
        					return FormValidation.error("Enter valid QID range");
        				}
        			} else {
        				Integer.parseInt(qid);
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid QID range/numbers");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckQidExcludeList(@QueryParameter String qidExcludeList) {
        	if (qidExcludeList == null || qidExcludeList.isEmpty()) {
        		return FormValidation.ok();
        	}
        	try {
        		String[] qidsString = qidExcludeList.split(",");
        		for (String qid : qidsString) {
        			if (qid.contains("-")) {
        				String[] range = qid.split("-");
        				int firstInRange = Integer.parseInt(range[0]);
        				int lastInRange = Integer.parseInt(range[1]);
        				
        				if (firstInRange > lastInRange) {
        					return FormValidation.error("Enter valid QID range");
        				}
        			} else {
        				Integer.parseInt(qid);
        			}
        		}
        	} catch (RuntimeException e) {
        		return FormValidation.error("Enter valid QID range/numbers");
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid QID range/numbers");
        	}
        	return FormValidation.ok();
        }
        
        @POST
        public FormValidation doCheckConnection(@QueryParameter String apiServer, @QueryParameter String credentialsId,
        		@QueryParameter String proxyServer, @QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId,
        		@QueryParameter boolean useProxy, @AncestorInPath Item item) {
        	item.checkPermission(Item.CONFIGURE);
        	String apiUser = "";
    		String apiPass = "";
    		String proxyUsername = "";
    		String proxyPassword = "";
        	try {
        		apiServer = apiServer.trim();
				apiServer =QualysGlobalConfig.get().getPortalUrl(apiServer);
        		logger.info("Using qualys API Server URL: " + apiServer);
        		FormValidation apiServerValidation = doCheckApiServer(apiServer);
        		FormValidation proxyServerValidation = doCheckProxyServer(proxyServer);
        		FormValidation proxyPortValidation = doCheckProxyPort(proxyPort);
        		
    			List<String> invalidFields = new ArrayList<String>();
    			if(apiServerValidation != FormValidation.ok()) 
    				invalidFields.add("API Server URL");
    			if(StringUtils.isBlank(credentialsId))
    				invalidFields.add("Credentials");
    			if(useProxy) {
    				if(proxyServerValidation != FormValidation.ok()) {
    					invalidFields.add("Proxy Server");
    				}
    				if(proxyPortValidation != FormValidation.ok()) {
    					invalidFields.add("Proxy Port");
    				}
    			}
    			if(!invalidFields.isEmpty())
    				return FormValidation.error("Invalid inputs for the following fields: " + String.join(", ", invalidFields));

                QualysAuth auth = new QualysAuth();

    			if (StringUtils.isNotEmpty(credentialsId)) {
                    StandardCredentials credentials = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                    StandardCredentials.class,
                                    item,
                                    null,
                                    Collections.<DomainRequirement>emptyList()),
                            CredentialsMatchers.withId(credentialsId));
                    if (credentials instanceof StandardUsernamePasswordCredentials) {
                        StandardUsernamePasswordCredentials userPass = (StandardUsernamePasswordCredentials) credentials;
                        apiUser = (userPass != null ? userPass.getUsername() : "");
                        apiPass = (userPass != null ? userPass.getPassword().getPlainText() : "");
                        auth.setQualysCredentials(apiServer, AuthType.Basic, apiUser, apiPass,"","");
                    } else if (credentials instanceof OAuthCredential) {
                        OAuthCredential oauth = (OAuthCredential) credentials;
                        String clientId = oauth.getClientId();
                        String clientSecret = oauth.getClientSecret();
                        auth.setQualysCredentials(apiServer,AuthType.OAuth,"","",clientId,clientSecret);
                    } else {
                        // handle unknown credential type
                        throw new IllegalArgumentException("Unsupported credential type: " + credentials.getClass());
                    }
                }


                if (StringUtils.isNotEmpty(proxyCredentialsId)) {

                    StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                    StandardUsernamePasswordCredentials.class,
                                    item,
                                    null,
                                    Collections.<DomainRequirement>emptyList()),
                            CredentialsMatchers.withId(proxyCredentialsId));

                    proxyUsername = (c != null ? c.getUsername() : "");
                    proxyPassword = (c != null ? c.getPassword().getPlainText() : "");
                }


                if(useProxy) {
	            	int proxyPortInt = Integer.parseInt(proxyPort);
	            	auth.setProxyCredentials(proxyServer, proxyUsername, proxyPassword, proxyPortInt);
            	}
            	QualysCSClient client = new QualysCSClient(auth, System.out);
            	
            	QualysCSTestConnectionResponse resp = client.testConnection();
            	logger.info("Received response : " + resp);
            	if(!resp.success) {
            		return FormValidation.error(resp.message);
    	   		}
            	return FormValidation.ok("Connection test successful!");
            }
        	catch(Exception e){
            	e.printStackTrace();
            	return FormValidation.error("Connection test failed. (Reason: Wrong inputs. Please check API Server and Proxy details.)");
            }
        }
        
        @POST
        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String credentialsId) {
        	StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                	return result.add(credentialsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(credentialsId);
                }
            }

            result.includeEmptyValue();
            // Username/Password: show "username (desc)"
            for (StandardUsernamePasswordCredentials c : CredentialsProvider.lookupCredentials(
                    StandardUsernamePasswordCredentials.class, item, ACL.SYSTEM, Collections.emptyList())) {
                String label = buildMaskedLabel(c.getUsername(), "*****", c.getDescription(), c.getId());
                result.add(label, c.getId());
            }

            // OAuth: show "clientId (desc)"
            for (OAuthCredential c : CredentialsProvider.lookupCredentials(
                    OAuthCredential.class, item, ACL.SYSTEM, Collections.emptyList())) {
                String clientId = safe(c.getClientId());
                String label = buildMaskedLabel(clientId, "*****", c.getDescription(), c.getId());
                result.add(label, c.getId());
            }

            return result.includeCurrentValue(credentialsId);
        }
        
        @POST
        public ListBoxModel doFillProxyCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String proxyCredentialsId) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                	return result.add(proxyCredentialsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(proxyCredentialsId);
                }
            }
            return result
                    .withEmptySelection()
                    .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                    .withMatching(CredentialsMatchers.withId(proxyCredentialsId));
        }
        
        public FormValidation doCheckProxyServer(@QueryParameter String proxyServer) {
            try {
            	Pattern patt = Pattern.compile(PROXY_REGEX);
                Matcher matcher = patt.matcher(proxyServer);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Enter valid server url!");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }

        public FormValidation doCheckProxyPort(@QueryParameter String proxyPort) {
        	try {
        		if (proxyPort != null && !proxyPort.isEmpty() && proxyPort.trim().length() > 0) {
        			int proxyPortInt = Integer.parseInt(proxyPort);
        			if(proxyPortInt < 1 || proxyPortInt > 65535) {
        				return FormValidation.error("Please enter a valid port number!");
        			}
        		}else {
        			return FormValidation.error("Please enter a valid port number!");
        		}
        	} catch (RuntimeException e) {
        		return FormValidation.error("Enter valid port number!");
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid port number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckImageIds(@QueryParameter String imageIds) {
        	if (StringUtils.isBlank(imageIds))
	        {
        		FormValidation.error("Image Ids cannot be empty");
	        } else {
	        	String[] imageIdsString = imageIds.split(",");
        		for (String imageId : imageIdsString) {
        			 Pattern pattern = Pattern.compile(Helper.IMAGE_ID_REGEX);
    	       		 Matcher matcher = pattern.matcher(imageId.trim());
    	       		 if (!matcher.find()){
    	       			Pattern pattern2 = Pattern.compile(Helper.IMAGE_NAME_REGEX);
       	       		 	Matcher matcher2 = pattern2.matcher(imageId.trim());
       	       		 	if (!matcher2.find()) {
       	       		 		Pattern pattern3 = Pattern.compile(Helper.IMAGE_ENV_VAR);
       	       		 		Matcher matcher3 = pattern3.matcher(imageId.trim());
       	       		 		if (!matcher3.find()) {
       	       		 			FormValidation.error(imageId.trim() + " is not a valid image ID or name");
       	       		 		}
       	       		 	}
    	       		 }
        		}
	        }
        	return FormValidation.ok();
        }
    }
}
