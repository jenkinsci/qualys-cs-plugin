package com.qualys.plugins.containerSecurity.common.QualysCriteria;

import com.google.gson.*;

import java.util.HashMap;

public class CvssCriteria {
    String version;
    double configuredScore;
    int found;
    HashMap<String, Integer> foundMap;
    boolean checkPotentialVulns = false;

    public CvssCriteria(JsonObject cvssFilter) {
        this.processFilter(cvssFilter);
    }
    public CvssCriteria(JsonObject cvssFilter, boolean checkPotentialVulns) {
        this.checkPotentialVulns = checkPotentialVulns;
        this.processFilter(cvssFilter);
    }

    private void processFilter(JsonObject cvssFilter) {
        version = "";
        configuredScore = 0.0;
        found = 0;
        foundMap = new HashMap<>();
        version = cvssFilter.get("version").getAsString();
        if (version.equals("2")) {
            version = "";
        }
        configuredScore = cvssFilter.get("configured").getAsDouble();
    }

    public JsonObject evaluate(JsonArray vulns) {
        JsonObject cvssResult = new JsonObject();
        cvssResult.addProperty("configured", configuredScore);
        String cvssVersion = String.format("cvss%sInfo", version);
        found=0;
        foundMap = new HashMap<>();

        for (JsonElement vuln : vulns) {
            JsonObject vulnObject = vuln.getAsJsonObject();
            String typeDetected = "";
            if (vulnObject.has("typeDetected")) {
                typeDetected = vulnObject.get("typeDetected").getAsString();
            }

            if (typeDetected.equals("POTENTIAL") && !checkPotentialVulns)
                continue;
            if (cvssVersion.equals("cvssmaxOfv2andv3Info")){
                if ((vulnObject.has("cvssInfo") && !vulnObject.get("cvssInfo").isJsonNull()) || (vulnObject.has("cvss3Info") && !vulnObject.get("cvss3Info").isJsonNull()) ) {
                    JsonObject cvss2Object = vulnObject.get("cvssInfo").getAsJsonObject();
                    String cvss2baseScoreString = cvss2Object.get("baseScore").getAsString();
                    double cvss2baseScore = Double.parseDouble(cvss2baseScoreString);
                    JsonObject cvss3Object = vulnObject.get("cvss3Info").getAsJsonObject();
                    String cvss3baseScoreString = cvss3Object.get("baseScore").getAsString();
                    double cvss3baseScore = Double.parseDouble(cvss3baseScoreString);
                    double baseScore = Math.max(cvss2baseScore,cvss3baseScore);
                    String baseScoreString = String.valueOf(baseScore);
                    if (baseScore >= configuredScore) {
                        found++;
                        if (!foundMap.containsKey(baseScoreString)) {
                            foundMap.put(baseScoreString, 0);
                        }
                        Integer currentCount = foundMap.get(baseScoreString);
                        currentCount++;
                        foundMap.put(baseScoreString, currentCount);
                    }
                }
            }
            else{
                if (vulnObject.has(cvssVersion) && !vulnObject.get(cvssVersion).isJsonNull()) {
                    JsonObject cvssObject = vulnObject.get(cvssVersion).getAsJsonObject();
                    String baseScoreString = cvssObject.get("baseScore").getAsString();
                    double baseScore = Double.parseDouble(baseScoreString);
                    if (baseScore >= configuredScore) {
                        found++;
                        if (!foundMap.containsKey(baseScoreString)) {
                            foundMap.put(baseScoreString, 0);
                        }
                        Integer currentCount = foundMap.get(baseScoreString);
                        currentCount++;
                        foundMap.put(baseScoreString, currentCount);
                    }
                }
            }
        }

        cvssResult.addProperty("found", found);
		cvssResult.addProperty("version", version);
        if (found > 0) {
            cvssResult.addProperty("result", false); // criteria not satisfied
            Gson gson = new GsonBuilder().create();
            String foundMapJson = gson.toJson(foundMap);
            JsonParser parser = new JsonParser();
            JsonObject foundMapObject = parser.parse(foundMapJson).getAsJsonObject();
            cvssResult.add("foundMap", foundMapObject);
        } else {
            cvssResult.addProperty("result", true); // criteria satisfied
        }

        return cvssResult;
    }
}
