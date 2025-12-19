package com.qualys.plugins.containerSecurity.common.QualysCriteria;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.Set;

public class SoftwareCriteria {
    ArrayList<String> filters;
    JsonObject criteriaObject;
    Set<String> namesSet;
    ArrayList<JsonObject> namesFound;
    ArrayList<String> softwareFound;

    public SoftwareCriteria(JsonArray softwareFilter) {
        this.filters = new ArrayList<>(0);
        this.namesFound = new ArrayList<>(0);
        this.softwareFound = new ArrayList<>(0);
        this.criteriaObject = new JsonObject();

        for (JsonElement software : softwareFilter) {
            String filter = software.getAsString();
            this.filters.add(filter);

            JsonObject swFilterObject = this.getSoftwareNameAndVersion(filter);
            String name = swFilterObject.get("name").getAsString().toLowerCase();
            if (!this.criteriaObject.has(name)) {
                this.criteriaObject.add(name, new JsonArray());
            }
            
            swFilterObject.remove("name"); // now that name is key in criteriaObject. not needed here.
            JsonArray conditions = this.criteriaObject.get(name).getAsJsonArray();
            conditions.add(swFilterObject);
        }
        this.namesSet = this.criteriaObject.keySet();
    }

    private JsonObject getSoftwareNameAndVersion(String filter) {
        String splitOn = "";
        JsonObject swFilterObject = new JsonObject();
        swFilterObject.add("name", JsonNull.INSTANCE);
        swFilterObject.add("operator", JsonNull.INSTANCE);
        swFilterObject.add("version", JsonNull.INSTANCE);

        if (filter.contains(">=")) {
            splitOn = ">=";
        } else if (filter.contains("<=")) {
            splitOn = "<=";
        } else if (filter.contains(">")) {
            splitOn = ">";
        } else if (filter.contains("<")) {
            splitOn = "<";
        } else if (filter.contains("=")) {
            splitOn = "=";
        }

        if (!splitOn.equals("")) {
            String[] filterParts = filter.split(splitOn);
            swFilterObject.addProperty("name", filterParts[0]);
            swFilterObject.addProperty("operator", splitOn);
            swFilterObject.addProperty("version", filterParts[1]);
        } else {
            swFilterObject.addProperty("name", filter);
        }

        return swFilterObject;
    }

    public JsonObject evaluate(JsonArray softwareArray) {
    	
        for (JsonElement softwareElement : softwareArray) {
            JsonObject software = softwareElement.getAsJsonObject();
            String name = software.get("name").getAsString();
            
            for (String n : this.namesSet) {
	            if (name.toLowerCase().matches(n)) {
	            	software.addProperty("criteriaKey", n);
	                this.namesFound.add(software);
	            }
            }
        }

        if (this.namesFound.size() > 0) {
            for (JsonObject software : this.namesFound) {
                boolean matches = this.compareSoftware(software);
                if (matches) {
                    software.remove("vulnerabilities");
                    String matched = software.get("name").getAsString() + "=" + software.get("version").getAsString();
                    this.softwareFound.add(matched);
                }
            }
        }

        String configured = this.filters.toString().replace("[","").replace("]", "");
        String found = this.softwareFound.toString().replace("[","").replace("]", "");

        JsonObject softwareResult = new JsonObject();
        softwareResult.addProperty("configured", configured);
        softwareResult.addProperty("found", found);

        if (this.softwareFound.size() > 0) {
            softwareResult.addProperty("result", false);
        } else {
            softwareResult.addProperty("result", true);
        }

        return softwareResult;
    }

    private boolean compareSoftware(JsonObject software) {
        String name = software.get("criteriaKey").getAsString().toLowerCase();
        JsonArray filtersArray = this.criteriaObject.getAsJsonArray(name);
        boolean result = false;

        for (JsonElement filter : filtersArray) {
            JsonObject configuredFilter = filter.getAsJsonObject();
            
            if (configuredFilter.get("operator").isJsonNull()) {
                result = result || true;
            } else if (configuredFilter.get("operator").getAsString().equals("=") &&
                    software.get("version").getAsString().matches(configuredFilter.get("version").getAsString())) {
                result = result || true;
            }
        }

        return result;
    }
}
