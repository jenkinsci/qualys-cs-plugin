package com.qualys.plugins.containerSecurity.config;

import java.io.File;
import java.util.*;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.qualys.plugins.containerSecurity.common.QualysAuth.AuthType;
import com.qualys.plugins.containerSecurity.common.QualysAuth.QualysAuth;
import com.qualys.plugins.containerSecurity.common.QualysClient.QualysCSClient;
import com.qualys.plugins.containerSecurity.common.QualysClient.QualysCSTestConnectionResponse;
import com.qualys.plugins.containerSecurity.util.OAuthCredential;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import hudson.security.ACL;
import net.sf.json.JSONObject;

import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.qualys.plugins.containerSecurity.GetImageVulnsNotifier;
import com.qualys.plugins.containerSecurity.util.Helper;

import hudson.Extension;
import hudson.XmlFile;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import hudson.util.XStream2;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;

import org.apache.commons.lang.StringUtils;



import static com.qualys.plugins.containerSecurity.util.Helper.buildMaskedLabel;
import static com.qualys.plugins.containerSecurity.util.Helper.safe;


@Extension
public class QualysGlobalConfig extends GlobalConfiguration {
	
	private String apiServer;
	private String platform;
	private String credentialsId;
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
    private int proxyPort;
    private String proxyCredentialsId;
    private String proxyUsername;
    private Secret proxyPassword;
    private boolean useProxy = false;
    private String excludeBy;
    private boolean isExcludeConditions;
    private String excludeList;

    private boolean isFailOnQidFound;
    private String qidList;
    private boolean isFailOnCVEs;
	private String cveList;
    private boolean isFailOnSoftware = false;
    private String softwareList;
    
    private boolean isPotentialVulnsToBeChecked = false;
	private String webhookUrl;
	private String dockerUrl = "unix:///var/run/docker.sock";
	private String dockerCert;
	
	private String cvssVersion;
    private String cvssThreshold;
    private boolean failByCvss = false;
	
	private final String URL_REGEX = "^(https?)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    private final String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&@#/%?=~_|!,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    private final String TIMEOUT_PERIOD_REGEX = "^(\\d+[*]?)*(?<!\\*)$";
	
	private static final XStream2 XSTREAM2 = new XStream2();
	private final static Logger logger = Logger.getLogger(GetImageVulnsNotifier.class.getName());
	
	public QualysGlobalConfig() {
        load();
    }
	
	@Initializer(before = InitMilestone.PLUGINS_STARTED)
    public static void xStreamCompatibility() {
        XSTREAM2.addCompatibilityAlias("jenkins.plugins.qualys_cs.QualysCS$DescriptorImpl", QualysGlobalConfig.class);
        XSTREAM2.addCompatibilityAlias("jenkins.plugins.qualys_cs.util.NameValuePair", QualysGlobalConfig.class);
    }

    @Override
    protected XmlFile getConfigFile() {
        Jenkins j = Jenkins.getInstance();
        File rootDir = j.getRootDir();
        File xmlFile = new File(rootDir, "jenkins.plugins.qualys_cs.QualysCS.xml");
        return new XmlFile(XSTREAM2, xmlFile);
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException
    {
        req.bindJSON(this, json);
        save();
        return true;
    }
    
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
    	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
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
    


    
    public FormValidation doCheckCveList(@QueryParameter String cveList) {
    	if(! Helper.isValidCVEList(cveList)) {
    		return FormValidation.error("Enter valid CVEs!");
    	}
    	return FormValidation.ok();
    }
    
    @POST
    public FormValidation doCheckConnection(@QueryParameter String apiServer, @QueryParameter String credentialsId, @QueryParameter String proxyServer, @QueryParameter String proxyPort,
    		@QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, @AncestorInPath Item item) {
    	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
    	String apiUser = "";
        String apiPass = "";
        String proxyUsername = "";
		String proxyPassword = "";
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
                auth.setQualysCredentials(apiServer, AuthType.Basic,apiUser,apiPass,"","");
            } else if (credentials instanceof OAuthCredential) {
                OAuthCredential oauth = (OAuthCredential) credentials;
                String clientId = oauth.getClientId();
                String clientSecret = oauth.getClientSecret();
                auth.setQualysCredentials(apiServer, AuthType.OAuth,"","",clientId,clientSecret);
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
            	
    	try {
    		apiServer = apiServer.trim();
			apiServer = getPortalUrl(apiServer);
    		logger.info("Using qualys API Server URL: " + apiServer);
    		FormValidation apiServerValidation = doCheckApiServer(apiServer);
    		FormValidation proxyServerValidation = doCheckProxyServer(proxyServer);
    		FormValidation proxyPortValidation = doCheckProxyPort(proxyPort);
    		
			List<String> invalidFields = new ArrayList<String>();
			if(apiServerValidation != FormValidation.ok()) 
				invalidFields.add("API Server URL");
			if(credentialsId == null || StringUtils.isBlank(credentialsId))
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

            if (useProxy) {
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
    	} catch (RuntimeException e) {
    		return FormValidation.error("Enter valid QID range/numbers");
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

	public String getPortalUrl(String apiServerURL)
	{
		String SCP_URL_PREFIX="https://qualysguard.";
		String PCP_URL_PREFIX = "https://qualysgateway.";
		String [] arr = apiServerURL.split("\\.");
		String rest_url=String.join(".", Arrays.copyOfRange(arr, 1, arr.length));
		String portalUrl="";

		// String Compariosn includes qualys. and apps.qualys as Server URL contains either qualys or only apps.qualys.
		// If it does not suffice the above condition it is PCP Server URL
		if (rest_url.contains("qualys.") || rest_url.contains("apps.qualys")) {
			portalUrl = SCP_URL_PREFIX + rest_url;
		} else {
			portalUrl = PCP_URL_PREFIX + rest_url;
		}
		logger.info("Converting serverUrl: " + apiServerURL + " to portalUrl:" + portalUrl);
		return portalUrl;
	}
    public static QualysGlobalConfig get() {
        return GlobalConfiguration.all().get(QualysGlobalConfig.class);
    }
    
    public String getApiServer() {
    	return apiServer;
    }
    
    
    
    public void setApiServer(String arg) {
    	this.apiServer = arg.trim();
    }
    
    public String getPlatform() {
        return platform;
    }
    
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    
    public void setPollingInterval(String poll) {
    	this.pollingInterval = poll;
    }
    public String getPollingInterval() {
    	return this.pollingInterval;
    }
    
    public void setVulnsTimeout(String poll) {
    	this.vulnsTimeout = poll;
    }
    public String getVulnsTimeout() {
    	return this.vulnsTimeout;
    }
    
    public boolean getIsFailOnSevereVulns() {
    	return this.isFailOnSevereVulns;
    }
    public void setIsFailOnSevereVulns(boolean failOnSev) {
    	this.isFailOnSevereVulns = failOnSev;
    }
    
    public void setSeverity1Limit(int limit) {
    	this.severity1Limit = limit;
    }
    public int getSeverity1Limit() {
    	return this.severity1Limit;
    }
    
    public void setSeverity2Limit(int limit) {
    	this.severity2Limit = limit;
    }
    public int getSeverity2Limit() {
    	return this.severity2Limit;
    }
    
    public void setSeverity3Limit(int limit) {
    	this.severity3Limit = limit;
    }
    public int getSeverity3Limit() {
    	return this.severity3Limit;
    }
    
    public void setSeverity4Limit(int limit) {
    	this.severity4Limit = limit;
    }
    public int getSeverity4Limit() {
    	return this.severity4Limit;
    }
    
    public void setSeverity5Limit(int limit) {
    	this.severity5Limit = limit;
    }
    public int getSeverity5Limit() {
    	return this.severity5Limit;
    }
    
    public void setIsSev1Vulns(boolean sev) {
    	this.isSev1Vulns = sev;
    }
    public boolean getIsSev1Vulns() {
    	return this.isSev1Vulns;
    }

    public void setIsSev2Vulns(boolean sev) {
    	this.isSev2Vulns = sev;
    }
    public boolean getIsSev2Vulns() {
    	return this.isSev2Vulns;
    }
    public void setIsSev3Vulns(boolean sev) {
    	this.isSev3Vulns = sev;
    }
    public boolean getIsSev3Vulns() {
    	return this.isSev3Vulns;
    }
    public void setIsSev4Vulns(boolean sev) {
    	this.isSev4Vulns = sev;
    }
    public boolean getIsSev4Vulns() {
    	return this.isSev4Vulns;
    }
    
    public void setIsSev5Vulns(boolean sev) {
    	this.isSev5Vulns = sev;
    }
    public boolean getIsSev5Vulns() {
    	return this.isSev5Vulns;
    }
    
    public void setProxyServer(String server) {
    	this.proxyServer = server;
    }
    public String getProxyServer() {
    	return this.proxyServer;
    }
    
    public void setProxyPort(int port){
    	this.proxyPort = port;
    }
    public int getProxyPort(){
    	return this.proxyPort;
    }
    
    public void setProxyCredentialsId(String proxyCredentialsId){
    	this.proxyCredentialsId = proxyCredentialsId;
    }
    public String getProxyCredentialsId(){
    	return this.proxyCredentialsId;
    }
    
    public void setUseProxy(boolean useProxy) {
    	this.useProxy = useProxy;
    }
    public boolean getUseProxy() {
    	return this.useProxy;
    }

    public void setIsFailOnQidFound(boolean isFail) {
    	this.isFailOnQidFound = isFail;
    }
    public boolean getIsFailOnQidFound() {
    	return this.isFailOnQidFound;
    }
    
    public boolean getFailByCvss() {return failByCvss;}
   	@DataBoundSetter
   	public void setFailByCvss(boolean failByCvss) {this.failByCvss = failByCvss;}
   	
   	public String getCvssVersion() {return cvssVersion;}
   	@DataBoundSetter
   	public void setCvssVersion(String cvssVersion) {this.cvssVersion = cvssVersion;}
   	
   	public String getCvssThreshold() {return cvssThreshold;}
   	@DataBoundSetter
   	public void setCvssThreshold(String cvssThreshold) {this.cvssThreshold = cvssThreshold;}
    
    public void setQidList(String qidList){
    	this.qidList = qidList;
    }
    public String getQidList(){
    	return this.qidList;
    }
    
    public boolean getIsPotentialVulnsToBeChecked() {
    	return this.isPotentialVulnsToBeChecked;
    }
    public void setIsPotentialVulnsToBeChecked(boolean potential) {
    	this.isPotentialVulnsToBeChecked = potential;
    }
    
    public void setCredentialsId(String cred) {
    	this.credentialsId = cred;
    }

	public String getCredentialsId() {
		return credentialsId;
	}
	
	public String getWebhookUrl() {
		return this.webhookUrl;
	}
	
	public void setWebhookUrl(String webhookUrl) {
		this.webhookUrl = webhookUrl;
	}

	public boolean getIsFailOnCVEs() {
		return this.isFailOnCVEs;
	}
	
	public String getProxyUsername() {return proxyUsername;}
	@DataBoundSetter
	public void setProxyUsername(String proxyUsername) {this.proxyUsername = proxyUsername;}
	
	public Secret getProxyPassword() {return proxyPassword;}
	@DataBoundSetter
	public void setProxyPassword(String proxyPassword) {this.proxyPassword = Secret.fromString(proxyPassword);}

	public String getCveList() {
		return this.cveList;
	}
	
	public void setIsFailOnCVEs(boolean isFailOnCVEs) {
		this.isFailOnCVEs = isFailOnCVEs;
	}

	public void setCveList(String list) {
		this.cveList = list;
	}
	
	public void setDockerUrl(String dockerUrl){
    	this.dockerUrl = dockerUrl;
    }
    public String getDockerUrl(){
    	return this.dockerUrl;
    }
    
    public void setDockerCert(String dockerCert){
    	this.dockerCert = dockerCert;
    }
    public String getDockerCert(){
    	return this.dockerCert;
    }
    
    public boolean getIsExcludeConditions() {
        return this.isExcludeConditions;
    }

    public void setIsExcludeConditions(boolean isExcludeConditions) {
        this.isExcludeConditions = isExcludeConditions;
    }
    
    public String getExcludeList() {
        return this.excludeList;
    }

    public void setExcludeList(String cveExcludeList) {
        this.excludeList = cveExcludeList;
    }
        
	public String getExcludeBy() {
        return this.excludeBy;
    }

    public void setExcludeBy(String excludeBy) {
        this.excludeBy = excludeBy;
    }
    
	public void setSoftwareList(String list) {
		this.softwareList = list;
	}
	
	public boolean getIsFailOnSoftware() {
		return isFailOnSoftware;
	}
	
	public void setIsFailOnSoftware(boolean software) {
		this.isFailOnSoftware = software;
	}

	public String getSoftwareList() {
		return softwareList;
	}
}