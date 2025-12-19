package com.qualys.plugins.containerSecurity.common.QualysCriteria;

import com.google.gson.*;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.stream.Collectors;

public class QualysCriteria {
	ArrayList<Integer> qidList;
	ArrayList<String> cveList;
	SoftwareCriteria softwareCriteria;
	CvssCriteria cvssCriteria;
	HashMap<Integer, Integer> severityMap;
	boolean checkPotentialVulns, sevStaus = true;
	ArrayList<Integer> qidExcludeList =  new ArrayList<>(0);
	ArrayList<String> cveExcludeList  = new ArrayList<>(0);
	String excludeBy = "";
	ArrayList<Integer> qidExcludeFound=  new ArrayList<>(0);
	ArrayList<String> cveExcludeFound  = new ArrayList<>(0);
	boolean finalImageStatus = true;
	ArrayList<String> failedReasons  = new ArrayList<>(0);
	Gson gsonObject = new Gson();
	public JsonObject returnObject;
	ArrayList<String> configuredQids;	
	ArrayList<Integer> qidsFound = new ArrayList<>(0);
	ArrayList<String> cvesFound = new ArrayList<>(0);
	

	public QualysCriteria(String criteriaJson) throws InvalidCriteriaException {
		JsonParser jsonParser = new JsonParser();
		JsonElement jsonTree = jsonParser.parse(criteriaJson);
		if (!jsonTree.isJsonObject()) {
			throw new InvalidCriteriaException();
		}

		this.setDefaultValues();
		JsonObject jsonObject = jsonTree.getAsJsonObject();
		if (jsonObject.has("failConditions")) {
			JsonObject failConditions = jsonObject.getAsJsonObject("failConditions");
			// QIDs
			if (failConditions.has("qids") && !failConditions.get("qids").isJsonNull()) {
				JsonArray qids = failConditions.getAsJsonArray("qids");				
				for (JsonElement qid : qids) {					
					String qidString = qid.getAsString();
					configuredQids.add(qidString);
					if (qidString.contains("-")) {
						String[] qidElements = qidString.split("-");
						int start = Integer.parseInt(qidElements[0]);
						int end = Integer.parseInt(qidElements[1]);
						for (int i = start; i <= end; i++) {
							this.qidList.add(i);
						}
					} else {
						this.qidList.add(Integer.parseInt(qidString));
					}
				}
					
			} else {
				System.out.println("'qids' not found in given JSON.");
			}
			
			// CVEs
			if (failConditions.has("cves") && !failConditions.get("cves").isJsonNull()) {
				JsonArray cves = failConditions.getAsJsonArray("cves");
				for (JsonElement cve : cves) {
					this.cveList.add(cve.getAsString());
				}
			} else {
				System.out.println("'cves' not found in given JSON.");
			}

			// Severities
			if (failConditions.has("severities") && !failConditions.get("severities").isJsonNull()) {
				JsonObject severities = failConditions.getAsJsonObject("severities");
				this.severityMap.put(1,
						!(severities.get("1") == null || severities.get("1").isJsonNull())
								? severities.get("1").getAsInt()
								: -1);
				this.severityMap.put(2,
						!(severities.get("2") == null || severities.get("2").isJsonNull())
								? severities.get("2").getAsInt()
								: -1);
				this.severityMap.put(3,
						!(severities.get("3") == null || severities.get("3").isJsonNull())
								? severities.get("3").getAsInt()
								: -1);
				this.severityMap.put(4,
						!(severities.get("4") == null || severities.get("4").isJsonNull())
								? severities.get("4").getAsInt()
								: -1);
				this.severityMap.put(5,
						!(severities.get("5") == null || severities.get("5").isJsonNull())
								? severities.get("5").getAsInt()
								: -1);
			} else {
				this.severityMap.clear();
				this.severityMap.put(1, -1);
				this.severityMap.put(2, -1);
				this.severityMap.put(3, -1);
				this.severityMap.put(4, -1);
				this.severityMap.put(5, -1);
				System.out.println("'severities' not found in given JSON.");
			}

			// Software Package
			if (failConditions.has("software") && !failConditions.get("software").isJsonNull()) {
				JsonArray softwareArray = failConditions.getAsJsonArray("software");
			    this.softwareCriteria = new SoftwareCriteria(softwareArray);
            } else {
			    System.out.println("'software' key not found in given JSON.");
            }

			// Check potential vulns as well?
			if (failConditions.has("checkPotentialVulns")) {
				this.checkPotentialVulns = failConditions.get("checkPotentialVulns").getAsBoolean();
			} else {
				System.out.println("'checkPotentialVulns' not found in given JSON.");
				this.checkPotentialVulns = false;
			}

			// CVSS criteria
			if (failConditions.has("cvss") && !failConditions.get("cvss").isJsonNull()) {
				JsonObject cvssObject = failConditions.getAsJsonObject("cvss");
				this.cvssCriteria = new CvssCriteria(cvssObject, this.checkPotentialVulns);
			} else {
				System.out.println("'cvss' key not found in given JSON.");
			}

			if(failConditions.has("excludeBy")&& !failConditions.get("excludeBy").isJsonNull()) {					
				//Exclude CVEs
				if (failConditions.get("excludeBy").getAsString().equals("cve")  && failConditions.has("excludeCVEs") && !failConditions.get("excludeCVEs").isJsonNull()) {
					excludeBy = "cve";
					JsonArray excludeCVEsList = failConditions.getAsJsonArray("excludeCVEs");
					for (JsonElement excludeCVEElement : excludeCVEsList) {
						String excludeCVEString = excludeCVEElement.getAsString();
						this.cveExcludeList.add(excludeCVEString);
					}				
					
				}
				
				// Exclude Qids
				if (failConditions.get("excludeBy").getAsString().equals("qid")  && failConditions.has("excludeQids") && !failConditions.get("excludeQids").isJsonNull()) {
					excludeBy = "qid";
					JsonArray excludeQidsList = failConditions.getAsJsonArray("excludeQids");
					for (JsonElement excludeQidElement : excludeQidsList) {
						String excludeQidString = excludeQidElement.getAsString();
						if (excludeQidString.contains("-")) {
							String[] excludeQids = excludeQidString.split("-");	
							int start = Integer.parseInt(excludeQids[0]);
							int end = Integer.parseInt(excludeQids[1]);
							for (int i = start; i <= end; i++) {
								this.qidExcludeList.add(i);
								
							}
							
						}else {
							this.qidExcludeList.add(Integer.parseInt(excludeQidString));
						}
						
					}
					
				}		
		}//excludeBy
			
			
		} else {
			System.out.println("'failConditions' not found in given JSON.");
		}
	}

	private void setDefaultValues() {
		this.qidList = new ArrayList<>(0);
		this.cveList = new ArrayList<>(0);
		this.configuredQids = new ArrayList<>(0);
		this.severityMap = new HashMap<>();
		

		this.checkPotentialVulns = false;

		this.returnObject = new JsonObject();
		returnObject.add("imageId", null);
		returnObject.add("imageSummary", null);
		returnObject.add("qids", null);
		returnObject.add("cveIds", null);
		returnObject.add("severities", null);
		returnObject.add("potentialVulnsBySev", null);
		returnObject.add("patchability", null);
		returnObject.add("vulnsTable", null);
		returnObject.add("softwaresTable", null);
		returnObject.add("layersTable", null);
		returnObject.add("qidExcludeFound", null);
		returnObject.add("cveExcludeFound", null);

	} // setDefaultValues

	/**
	 * refers exclude list and excludes vulnerability elements accordingly
	 * @param vulns JsonArray
	 * @return JsonArray
	 */
	private JsonArray excludeVulns(JsonArray vulns) {
		JsonArray vulnsAfterExclusion = new JsonArray();

		for (JsonElement vuln : vulns) {
			JsonObject vulnObject = vuln.getAsJsonObject();
			if (this.excludeBy.equals("qid")) {
				int qid = vulnObject.get("qid").getAsInt();

				if (!this.qidExcludeList.contains(qid)) {
					vulnsAfterExclusion.add(vuln);
				}
			} else if (this.excludeBy.equals("cve")) {
				JsonArray cveIds = new JsonArray();
				if (vulnObject.has("cveids") && !vulnObject.get("cveids").isJsonNull()) {
					cveIds = vulnObject.getAsJsonArray("cveids");
				}

				if (cveIds.size() == 0) {
					vulnsAfterExclusion.add(vuln);
					continue; // no CVEs to check here
				}

				int countOfCvesInExcludeList = 0;
				for (JsonElement cve : cveIds) {
					String cveString = cve.getAsString();

					if (this.cveExcludeList.contains(cveString)) {
						countOfCvesInExcludeList++;
					}
				}

				if(countOfCvesInExcludeList < cveIds.size()) {
					vulnsAfterExclusion.add(vuln);
				}
			}
		}
		return vulnsAfterExclusion;
	} // excludeVulns

	public Boolean evaluate(JsonObject response) {	
		Boolean finalImageStatus=true, sevStatus=true, qidStatus=true, cveStatus=true, softStatus=true;
		Boolean cvssStatus = true;
			
		if (response.has("vulnerabilities") && !response.get("vulnerabilities").isJsonNull()) {

			JsonArray vulns = response.getAsJsonArray("vulnerabilities");
			
			returnObject.add("vulnsTable", vulns); // Add Vulnerabilities
			
			// Evaluate Severity 
			sevStatus = this.evaluateSev(vulns);
			qidStatus = this.evaluateQids(vulns);
			cveStatus = this.evaluateCves(vulns);

			if (this.cvssCriteria != null) {
				JsonArray vulnsForEvaluation = vulns;
				if(!this.excludeBy.trim().equals("") ) {
					vulnsForEvaluation = this.excludeVulns(vulns);
				}
				JsonObject cvssResult = this.cvssCriteria.evaluate(vulnsForEvaluation);
				this.returnObject.add("cvss", cvssResult);
				cvssStatus = cvssResult.get("result").getAsBoolean();
			} else {
				JsonObject cvssResult = new JsonObject();
				cvssResult.add("configured", JsonNull.INSTANCE);
				cvssResult.add("found", JsonNull.INSTANCE);
				cvssResult.addProperty("result", true);
				this.returnObject.add("cvss", cvssResult);
			}

			// find distinct values
			JsonObject qidsJsonObject = this.returnObject.getAsJsonObject("qids");
			if(!this.qidExcludeFound.isEmpty()) {
				this.qidExcludeFound = (ArrayList<Integer>) this.qidExcludeFound.stream().distinct().collect(Collectors.toList());
				String qidExcludeFoundString = this.qidExcludeFound.toString().replace("[","").replace("]", "");
				qidsJsonObject.addProperty("excluded", qidExcludeFoundString);
			}else {
				qidsJsonObject.add("excluded", null);
			}		
			
			
			JsonObject cveJsonObject = this.returnObject.getAsJsonObject("cveIds");
			if(!this.cveExcludeFound.isEmpty()) {
				this.cveExcludeFound = (ArrayList<String>) this.cveExcludeFound.stream().distinct().collect(Collectors.toList());
				String cveExcludeFoundString = this.cveExcludeFound.toString().replace("[","").replace("]", "");
				cveJsonObject.addProperty("excluded", cveExcludeFoundString);
			}else {
				cveJsonObject.add("excluded", null);
			}
		}

		JsonArray softwareArray = new JsonArray();
		if(response.has("softwares") && !response.get("softwares").isJsonNull()) { //If software present then only check
			softwareArray = response.getAsJsonArray("softwares");
		}
		
		
		if (this.softwareCriteria != null) { 
            JsonObject softwareResult = this.softwareCriteria.evaluate(softwareArray);
            this.returnObject.add("software", softwareResult);
            softStatus =   softwareResult.get("result").getAsBoolean();
            
        }else {
        	 JsonObject softwareResult = new JsonObject();
             softwareResult.add("configured", JsonNull.INSTANCE);
             softwareResult.add("found", JsonNull.INSTANCE);
             softwareResult.addProperty("result", true);
             this.returnObject.add("software", softwareResult);
        }

		// Add software
		if(response.has("softwares") && !response.get("softwares").isJsonNull()) {
			returnObject.add("softwaresTable", response.getAsJsonArray("softwares"));
		}	
		// Add layers
		if(response.has("layers") && !response.get("layers").isJsonNull()) {
			returnObject.add("layersTable", response.getAsJsonArray("layers"));
		}	
		// Add ImageSummary
		JsonArray tagsArray = null;
		

		if (response.has("repo") && !response.get("repo").isJsonNull())
			tagsArray = this.getTags(response.getAsJsonArray("repo")); // collect al tags
		
		
		if(!sevStatus || !qidStatus || !cveStatus || !softStatus || !cvssStatus) {
			finalImageStatus = false;
		}

		JsonObject imageSummary = new JsonObject();
		imageSummary.addProperty("pass", finalImageStatus);
		imageSummary.add("Tags", tagsArray);
		imageSummary.add("size", response.get("size"));
		imageSummary.add("uuid", response.get("uuid"));
		imageSummary.add("sha", response.get("sha"));
		imageSummary.add("repo", response.get("repo"));
		imageSummary.add("operatingSystem", response.get("operatingSystem"));
		imageSummary.add("layersCount", response.get("layersCount"));
		imageSummary.add("dockerVersion", response.get("dockerVersion"));
		imageSummary.add("architecture", response.get("architecture"));

		returnObject.add("imageSummary", imageSummary);

		// Add Image ID
		if (response.has("imageId") && !response.get("imageId").isJsonNull()) {
			returnObject.add("imageId", response.get("imageId"));
		}
		// finally, return the result map
		
		return finalImageStatus;
	}

    private void addSeverities(HashMap<Integer, Integer> counts) {
    	
		HashMap<Integer, JsonObject> severityResult = new HashMap<Integer, JsonObject>();		
			for (int i = 5; i >= 1; --i) {
				boolean result = true;
				if (this.severityMap.get(i) != -1) {
					if (counts.get(i) > this.severityMap.get(i)) {
						result = false;
						if (sevStaus)
							sevStaus = false;
					}
				}
	
				JsonObject sevJson = new JsonObject();
				//sys
				if(this.severityMap.get(i).intValue() > -1) {
					sevJson.addProperty("configured", this.severityMap.get(i).intValue());
				}else {
					sevJson.add("configured", null);
				}
				if(counts.get(i) > 0) {
					sevJson.addProperty("found", counts.get(i));
				}else {
					if(this.severityMap.get(i).intValue() > -1) {
						sevJson.addProperty("found", 0);
					}else {
						sevJson.add("found", null);
					}	
					
				}
				
				sevJson.addProperty("result", result);
				severityResult.put(i, sevJson);	
				
	
			}		
			GsonBuilder builder = new GsonBuilder();
			gsonObject = builder.serializeNulls().create(); // for null values
			
			String sevVulnsJson = gsonObject.toJson(severityResult);
			JsonElement sevVulnsElement = gsonObject.fromJson(sevVulnsJson, JsonElement.class);
			returnObject.add("severities", sevVulnsElement);
			
		
		
		
	}

	private JsonArray getTags(JsonArray repoArray) {
		JsonArray tagsArray = new JsonArray();

		for (JsonElement repoDetails : repoArray) {
			JsonObject repoObject = repoDetails.getAsJsonObject();
			if (repoObject.has("tag"))
				tagsArray.add(repoObject.get("tag"));
		}

		return tagsArray;
	}

	public String getMyNumbersAsString(ArrayList<Integer> arrayList) {
		if(arrayList.isEmpty()) {
			return "";
		}		
		
		StringBuilder str = new StringBuilder();
		for (int i = 0; i < arrayList.size(); i++) {
			int myNumbersInt = arrayList.get(i);
			str.append(myNumbersInt + ",");
		}
		str.setLength(str.length() - 1);
		return str.toString();
	}
	
	public JsonObject getResult() {
		return this.returnObject;
	}
	
	public Boolean evaluateSev(JsonArray vulns) {
		
		// Default Hashmaps
		
		HashMap<Integer, Integer> evaluationSev = new HashMap<>();
		HashMap<Integer, Integer> confirmVulnsCount = new HashMap<>();
		HashMap<Integer, Integer> potentialVulnsCount = new HashMap<>();
		int patchable = 0, unpatchable = 0, totalVulnerabilities = 0,totalConfVuln = 0,totalPotlVuln = 0;
		for (int count = 1; count <= 5; count++) {				
			evaluationSev.put(count, 0);
			confirmVulnsCount.put(count, 0);
			potentialVulnsCount.put(count, 0);
		}
		
		boolean sevStatus = true;		
		
	
		
		
		for (JsonElement vuln : vulns) {	
			JsonObject vulnObject = vuln.getAsJsonObject();
			String typeDetected = "";
			int severity = 0;
			if (vulnObject.has("typeDetected")) {
				typeDetected = vulnObject.get("typeDetected").getAsString();
			}
			
			if (vulnObject.has("severity")) {
				severity = vulnObject.get("severity").getAsInt();
			}
			 			
			totalVulnerabilities++;
			
			 if (typeDetected.equals("POTENTIAL")) {
					int sevCount = potentialVulnsCount.get(severity) + 1;
					potentialVulnsCount.put(severity, sevCount);
					totalPotlVuln++;

				} else if (typeDetected.equals("CONFIRMED")) {
					int sevCount = confirmVulnsCount.get(severity) + 1;
					confirmVulnsCount.put(severity, sevCount);
					totalConfVuln++;
				}

				if (vulnObject.has("patchAvailable") && !vulnObject.get("patchAvailable").isJsonNull()) {
					boolean patchAvailable = vulnObject.get("patchAvailable").getAsBoolean();
					if (patchAvailable)
						patchable++;
					else
						unpatchable++;
				} else {
					unpatchable++;
				}
			
					
			if (typeDetected.equals("POTENTIAL") && !this.checkPotentialVulns) {
				continue;
			}			
			
			
			//following loop is get overall severity Status
			//if (this.severityMap.get(severity) != -1) { // that particular severity has configured.				
				int evaluationSevCount= evaluationSev.getOrDefault(severity, 0);
				if(excludeBy == "qid") {
						Integer qid = 0;
						if (vulnObject.has("qid")) {
							qid = vulnObject.get("qid").getAsInt();
						}
						
						if(this.qidExcludeList.contains(qid)) {
							qidExcludeFound.add(qid);
						}else {
							evaluationSevCount++;
							evaluationSev.put(severity, evaluationSevCount);
						}
					}else if(excludeBy == "cve") {		
						JsonArray cves = null;
						if (vulnObject.has("cveids")) {
							cves = vulnObject.get("cveids").getAsJsonArray();
						}						
						 
						int tempCount = 0;
						if(cves!=null && cves.size() > 0) {
							for (JsonElement cve : cves) {
								String cveString = cve.getAsString();
								if (this.cveExcludeList.contains(cveString)) {								
									cveExcludeFound.add(cveString);								
								}else {
									tempCount++;
								}
							}
						}else {
							tempCount++;
						}
						
						
						if(tempCount>0) {
							evaluationSevCount++;
							evaluationSev.put(severity, evaluationSevCount);							
						}
					}else {
						evaluationSevCount++;
						evaluationSev.put(severity, evaluationSevCount);
						
					}	
				
				
				   if(!this.severityMap.isEmpty() && this.severityMap.get(severity) != -1 && evaluationSev.get(severity) > this.severityMap.get(severity)) {
					   sevStatus = false;
					   failedReasons.add("Failing this image because found severity" +severity+" has more than configured after exclusion");					   
				   }				
			 //}  	   
			 
		}
		
		this.addSeverities(evaluationSev);
		
		
		String confirmVulnsJson = gsonObject.toJson(confirmVulnsCount);
		JsonElement confirmVulnsElement = gsonObject.fromJson(confirmVulnsJson, JsonElement.class);

		String potentialVulnsJson = gsonObject.toJson(potentialVulnsCount);
		JsonElement potentialVulnsElement = gsonObject.fromJson(potentialVulnsJson, JsonElement.class);

		returnObject.add("confirmedVulnsBySev", confirmVulnsElement);
		returnObject.add("potentialVulnsBySev", potentialVulnsElement);

		// Add Patchability
		JsonObject patchability = new JsonObject();
		patchability.addProperty("yes", patchable);
		patchability.addProperty("no", unpatchable);
		returnObject.add("patchability", patchability);
		
		returnObject.addProperty("totalVulnerabilities", totalVulnerabilities);
		returnObject.addProperty("potentialVulnsChecked", this.checkPotentialVulns);
		
		// Add tyepeDetected
		JsonObject typeDetected = new JsonObject();
		typeDetected.addProperty("Confirmed", totalConfVuln);
		typeDetected.addProperty("Potential", totalPotlVuln);
		returnObject.add("typeDetected", typeDetected);		
		
		return sevStatus;
	}
	
	public Boolean evaluateQids(JsonArray vulns) {
		Boolean qidStatus = true;
		
		for (JsonElement vuln : vulns) {	
			JsonObject vulnObject = vuln.getAsJsonObject();
			
			if (vulnObject.has("typeDetected") && vulnObject.get("typeDetected").getAsString().equals("POTENTIAL") && !this.checkPotentialVulns) {
				continue;	
			}			
			
				
			Integer qid = 0;
			if (vulnObject.has("qid")) {
				qid = vulnObject.get("qid").getAsInt();
			}
			
			
			if (this.qidList.contains(qid)) {
				qidsFound.add(qid);
			}
			
			
			if(excludeBy == "qid") {
				if (this.qidExcludeList.contains(qid)) {
					qidExcludeFound.add(qid);
					continue;
				}else if (!this.qidExcludeList.contains(qid) && this.qidList.contains(qid)) {					
					qidStatus = false;
					failedReasons.add("Failing this image because found qid - " +qid+" after exclusion");					
				}		
				
			}else if(excludeBy == "cve") {
				JsonArray cves = null;
				if (vulnObject.has("cveids")) {
					cves = vulnObject.get("cveids").getAsJsonArray();
				}	
				
				if((cves== null || cves.size() == 0) && qidsFound.contains(qid)) {
					qidStatus = false;					
					failedReasons.add("Failing this image because found qid - " +qid+" after exclusion");
				}
				
				
				for (JsonElement cve : cves) {
					String cveString = cve.getAsString();
					if (this.cveExcludeList.contains(cveString) ) {
						cveExcludeFound.add(cveString);
						continue;
					}else if (!this.cveExcludeList.contains(cveString) && this.qidList.contains(qid)) {
						qidStatus = false;
						failedReasons.add("Failing this image because found CVE - " +cveString+" after exclusion");												
					}
				}				
				
			}
		
		}// for vulns
		
			JsonObject qids = new JsonObject();
			
			if(configuredQids.size() > 0) {
				qids.addProperty("configured", String.join(",", configuredQids)); //configured
			}else {
				qids.add("configured", null); 
			}
			
			String foundQidsString =  this.getMyNumbersAsString(this.qidsFound);
			
			if(!foundQidsString.isEmpty()) {
				qids.addProperty("found", foundQidsString);
			}else {
				qids.add("found", null);  // add null we found nothing
			}
			
			
			
			if(excludeBy.isEmpty()) {
				if (qidsFound.size()>0) {					
					qidStatus = false;
					failedReasons.add("Failing this image because found qid(s) - " +qidsFound.toString());
				}
			}		
			
			qids.addProperty("result", qidStatus);
			returnObject.add("qids", qids);
		
			return qidStatus;
	
	
	
	}
	
	public Boolean evaluateCves(JsonArray vulns) {
		Boolean cveStatus = true;
		for (JsonElement vuln : vulns) {	
			JsonObject vulnObject = vuln.getAsJsonObject();
			if (vulnObject.has("typeDetected") && vulnObject.get("typeDetected").getAsString().equals("POTENTIAL") && !this.checkPotentialVulns) {
				continue;	
			}
			
			boolean partialCvetatus= true;
			
			JsonArray cves = null;
			if (vulnObject.has("cveids")) {
				cves = vulnObject.get("cveids").getAsJsonArray();
			}	
			for (JsonElement cve : cves) {
				String cveString = cve.getAsString();
				if (this.cveList.contains(cveString)) {
					partialCvetatus = false;
					if(!cvesFound.contains(cveString)){
						cvesFound.add(cveString);
					}
				}
			}
			
			if(excludeBy == "cve") {
				for (JsonElement cve : cves) {
					String cveString = cve.getAsString();
					if (this.cveExcludeList.contains(cveString)) {
						cveExcludeFound.add(cveString);
					}else if (this.cveList.contains(cveString) && !this.cveExcludeList.contains(cveString)) {
						cveStatus = false;
						failedReasons.add("Failing this image because found CVE - " +cveString+" after exclusion");						
					}
				}
				
			}else if(excludeBy == "qid") {
				Integer qid = 0;
				if (vulnObject.has("qid")) {
					qid = vulnObject.get("qid").getAsInt();
				}
				if (this.qidExcludeList.contains(qid)) {
					qidExcludeFound.add(qid);
					continue;
				}else if (!partialCvetatus && !this.qidExcludeList.contains(qid)) {					
					cveStatus = false;
					failedReasons.add("Failing this image because found qid - " +qid+" after exclusion");					
				}
				
			}
			
		}	
		
		//if (!this.cveList.isEmpty()) {
			JsonObject cvesJson = new JsonObject();
			if(cveList.size() > 0) {
				cvesJson.addProperty("configured", String.join(",", this.cveList)); //configured
			}else {
				cvesJson.add("configured", null);
			}
			
			
			
			//found
			if(!String.join(",", cvesFound).isEmpty()) {
				cvesJson.addProperty("found", String.join(",", cvesFound));
			}else {
				cvesJson.add("found", null);
			}	
			
					
			
			if(excludeBy.isEmpty()) {
				if(cvesFound.size() > 0) {
					cveStatus = false;
					failedReasons.add("Failing this image because found CVE - " +cvesFound.toString()+" after exclusion");
				}
			}
			
		//}	
			cvesJson.addProperty("result", cveStatus);
			returnObject.add("cveIds", cvesJson);
		
		return cveStatus;
		
	}

	public ArrayList<String> getBuildFailedReasons() {
		return (ArrayList<String>) this.failedReasons.stream().distinct().collect(Collectors.toList());
    }	
	
	
}