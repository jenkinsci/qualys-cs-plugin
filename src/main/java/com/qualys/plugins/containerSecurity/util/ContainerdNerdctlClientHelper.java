package com.qualys.plugins.containerSecurity.util;

import hudson.AbortException;
import qshaded.com.google.gson.JsonArray;
import qshaded.com.google.gson.JsonElement;
import qshaded.com.google.gson.JsonObject;
import qshaded.com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.logging.Logger;

public class ContainerdNerdctlClientHelper {
    private static final Logger logger = Logger.getLogger(ContainerdNerdctlClientHelper.class.getName());
    private static final String EXPORT_PATH_CMD = "export PATH=$PATH:";

    private static final String NERDCTL_VERSION_CMD = "nerdctl --version";
    private static final String LIST_CONTAINER_CMD = "nerdctl -n k8s.io ps --filter label=io.kubernetes.container.name=qualys-container-sensor --filter status=running --format=json";

    private static final String INSPECT_CONTAINER_CMD = "nerdctl -n k8s.io inspect ";
    private static final String INSPECT_IMAGE_CMD = "nerdctl -n k8s.io image inspect ";
    private static final String TAG_IMAGE_CMD = "nerdctl -n k8s.io tag ";
    private final PrintStream buildLogger;
    private final String nerdctlBinaryPath;

    private static final String IMAGE_SHA_ERROR_MSG = "Failed to extract image sha associated with ";
    private static final String NERDCTL_PATH_ERROR_MSG = "Failed to get containers list .Please check if nerdctl binary is added to the path.";

    public ContainerdNerdctlClientHelper(PrintStream buildLogger, String nerdctlBinaryPath) {
        this.buildLogger = buildLogger;
        this.nerdctlBinaryPath = nerdctlBinaryPath;
    }

    public boolean isCICDSensorUp() throws AbortException {
        this.validateNerdctlBinaryPath();
        JsonObject container = getContainerAsJsonObject();

        if (container != null) {
            if (container.has("Labels") && container.get("Labels").getAsString().contains("io.kubernetes.container.name=qualys-container-sensor")) {
                return checkForCICDMode(container.get("ID").getAsString());
            } else {
                buildLogger.println("Qualys CS sensor container is not runnning. Sensor won't be able to scan the image. Please check the sensor container.");
                throw new AbortException(
                        "Qualys CS sensor container is not runnning. Sensor won't be able to scan the image. Please check the sensor container.");
            }
        }
        buildLogger.println("Qualys CS sensor is not available on the host. Sensor won't be able to scan the image. Please check the sensor container.");
        throw new AbortException(
                "Qualys CS sensor is not available on the host. Sensor won't be able to scan the image. Please check the sensor container.");
    }

    private JsonObject getContainerAsJsonObject() {
        String command = EXPORT_PATH_CMD + this.nerdctlBinaryPath + ";" + LIST_CONTAINER_CMD;
        JsonObject containers;
        String containersInfo = this.executeCommand(command);
        try {
            if (containersInfo.startsWith("{")) {
                containers = JsonParser.parseString(containersInfo).getAsJsonObject();
            } else {
                buildLogger.println(NERDCTL_PATH_ERROR_MSG);
                throw new AbortException(NERDCTL_PATH_ERROR_MSG);
            }
            return containers;
        } catch (IOException e) {
            buildLogger.println("Failed to parse the " + command + " output " + NERDCTL_PATH_ERROR_MSG);
        }
        return null;
    }

    private boolean checkForCICDMode(String containerID) throws AbortException {
        String command = EXPORT_PATH_CMD + this.nerdctlBinaryPath + ";" + INSPECT_CONTAINER_CMD + containerID + " --format=json";
        String sensorInfo = this.executeCommand(command);
        try {
            JsonObject sensorInfoJson = JsonParser.parseString(sensorInfo).getAsJsonObject();
            JsonArray sensorArguments = sensorInfoJson.get("Args").getAsJsonArray();
            for (JsonElement arg : sensorArguments) {
                if (arg.getAsString().equals("--cicd-deployed-sensor") || arg.getAsString().equals("-c"))
                    return true;
            }
        } catch (Exception e) {
            String errorMsg = "Failed to check if the sensor is running in CICD mode ; Reason : " + e.getMessage();
            logger.info(errorMsg);
            throw new AbortException(errorMsg);
        }
        return false;
    }

    public String fetchImageSha(String image) throws AbortException {
        String command = EXPORT_PATH_CMD + this.nerdctlBinaryPath + ";" + INSPECT_IMAGE_CMD + image + " --format=json";
        String imagesha = "";
        String imageShaOutput = this.executeCommand(command);

        try {
            if (imageShaOutput.contains("Id")) {
                JsonObject imageInfo = JsonParser.parseString(imageShaOutput).getAsJsonObject();
                imagesha = imageInfo.get("Id").getAsString();
                String[] imageIds = imagesha.split(":");
                imagesha = imageIds[1];
                buildLogger.println("### Image sha for " + image + " is = " + imagesha);

            } else {
                buildLogger.println(IMAGE_SHA_ERROR_MSG + image + " check if the image is available on the host.");
                throw new AbortException(IMAGE_SHA_ERROR_MSG + image);
            }
        } catch (Exception e) {
            String errorMsg = IMAGE_SHA_ERROR_MSG + image + " ; Reason : " + e.getMessage();
            logger.info(errorMsg);
            throw new AbortException(errorMsg);
        }
        return imagesha;
    }

    public void tagImage(String name, String imageSha) throws AbortException {

        String command = EXPORT_PATH_CMD + this.nerdctlBinaryPath + ";" + TAG_IMAGE_CMD + name + " qualys_scan_target:" + imageSha;
        try {
            this.executeCommand(command);
            buildLogger.println("Image " + name + " tagged successfully ");
        } catch (Exception e) {
            for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
            buildLogger.println("Failed to tag the image " + name
                    + " with qualys_scan_target.. Reason : " + e.getMessage());
            throw new AbortException("Failed to tag the image " + name + " with qualys_scan_target.. Reason : "
                    + e.getMessage());
        }
    }

    public void validateNerdctlBinaryPath() throws AbortException {
        String command = EXPORT_PATH_CMD + this.nerdctlBinaryPath + ";" + NERDCTL_VERSION_CMD;
        String versionInfo = this.executeCommand(command);
        if (!versionInfo.toLowerCase().contains("version"))
            throw new AbortException("Nerdctl Binary path is not set properly.");
    }

    private String executeCommand(String command) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command("bash", "-c", command);
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            String commandOutput = "";
            while ((line = reader.readLine()) != null) {
                commandOutput = commandOutput + line;
            }
            process.destroy();
            return commandOutput;
        } catch (IOException e) {
            throw new RuntimeException("Failed to execute command " + command
                    + e.getMessage());
        }
    }
}
