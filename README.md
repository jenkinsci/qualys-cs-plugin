# Qualys Container Scanning Connector

## About

The Qualys Container Scanning Connector for Jenkins empowers DevOps to assess container images in their existing CI/CD processes with help of Qualys Container Security(CS) module. Integrating this assessment step will help you catch and eliminate container images related flaws. This plugin supports pipeline as well as free-style projects.

## How this plugin works

This Qualys CS plugin/connector automatically tags images built out of CI/CD pipeline with the tag qualys_scan_target:<image-id> to mark them for scanning by Qualys sensor and only those images are scanned for vulnerabilities. Once the scanning is over, Qualys Container Sensor will remove the tag. However, if an image has no other tag applied to it other than 'qualys_scan_target:<image-id>', the sensor will retain the tag to avoid removal of the image from the host.
The sensor uploads all the data for configured image to the Qualys platform. Qualys container Security module quickly analyzes it and responds with vulnerabilities. If you have configured any pass/fail criteria, the plugin evaluates the response against that. If it finds something is not matching your criteria, it will cause exception to fail your build. Otherwise, your build job proceeds to next step (if any). 

## How to use this plugin

### Prerequisites

* A valid Qualys subscription with the Container Security application activated.
* Access to Qualys Container Security application API endpoint from your build host.
* Requires the container sensor for CI/CD environment to be installed on the jenkins build host. Refer to Qualys Container Security Sensor Deployment Guide for instructions on installing the container cicd sensor. You must pass the following parameter while deploying the sensor for CI/CD environment --cicd-deployed-sensor or -c.
* Internet connection for slave to be able to connect to the Qualys Cloud Platform. Install sensor with proxy option if slave is running behind proxy. 
* The Jenkins master and slave nodes should have an open connection to the Qualys Cloud Platform in order to get data from the Qualys Cloud Platform for vulnerability reporting.

### Where to use this plugin step

We recommend using this plugin step during "Post-build" phase of your job, right after you build a container image. 

### Configuration
Before the Job configuration, make sure to configure the docker socket/containerd binary path for the plugin to be able to tag the image.
To configure the following fields, navigate to 'Qualys Container Security' section in the path as -> {Jenkins-Instance- 
url}/manage/configure > Qualys Container Security > Advanced Settings.
 * Docker URL/Nerdctl binary path: Configure this field as per your runtime environment.
    For dockerd, the expected configuration is docker socket path eg.
    unix://path_of_docker.sock or tcp://[host]:[port], in case of TLS, cert path should be provided in field 'Cert file path'
 * For containerd, the expected configuration is nerdctl binary path. eg. /var/nerdctl _binary
   As nerdctl binary is required for the plugin to complete its activities, it is advised to make it accessible for plugin by mapping the nerdctl binary path as well as the 
   containerd.sock file path in Jenkins deployment.yaml's volumeMounts section.
   Please refer the below sample :
   
   <img width="393" alt="image" src="https://github.com/jenkinsci/qualys-cs-plugin/assets/143092348/bf609084-9ba3-4420-a4d1-9435fe129b0c">
   
 * Cert File Path (optional): If you are using remote server enabled https, you can provide a specific folder location which contains the files ca.pem, cert.pem and 
   key.pem. For example, /var/jenkins_home/certs

## For Job Configuration
If you are using pipeline, you should go to "Pipeline Syntax", and select `getImageVulnsFromQualys` step.
If you are using freestyle, you should add `Scan container images with Qualys CS` build step.

A form appears with several input fields. Now you are ready to configure the plugin. 

#### Qualys Credentials

1. Enter your Qualys API server URL. 
2. Select/Add your Qualys API Credentials.
3. If you need proxy to communicate to the Internet, set correct proxy settings. 
4. To confirm that Jenkins can communicate to Qualys Cloud Platform and APIs, use `Test Connection` button.

#### Image Id/ Image name

The field Image IDs/Image Names is used to set the container image Ids or names you want to report on. The plugin will only pull a report for the image Ids/names you specify. It is a comma separated list. You can also provide image ids through an environment variable.  

#### Pass/Fail Criteria

You can optionally fail the build based on vulnerabilities. 

1. Configure to fail a build if the number of detections exceeds the limit specified for one or more severity types. For example, to fail a build if severity 5 vulnerabilities count is more than 2, select the 'Fail with more than severity 5' option and specify 2.
2. Configure to fail a build if the configured QIDs found in the scan result.
3. Configure to fail a build if the configured CVEs found in the scan result.
4. Configure to fail a build if configured softwares names are found in scan result.
5. Configure to fail build by CVSS Base score - This can be either using CVSS v2 or CVSS v3.

By default the pass/fail criteria is applied to Confirmed type of vulnerabilities. We can apply above fail conditions to potential vulnerabilities as well by configuring its checkbox.

You can also exclude some conditions - You can configure a comma separated list of either CVEs or QIDs to exclude from the build failure conditions.

### Generate Pipeline Script *(for pipeline project only)*

If you are configuring pipeline project, click the `Generate Pipeline Script` button. It will give you a command which you can copy and paste in your project's pipeline script. 

## Release Notes for v1.7.x
 * Users can now provide the Docker URL/Nerdctl path from the Job level configuration also.
 * Minor log changes.
 * For detailed information on upgrading of Qualys Container Scanning Connector to the 1.7.x version, please visit [user guide](https://www.qualys.com/docs/qualys-container-scanning-connector-jenkins-plugin-user-guide.pdf)

## Known Issues in v1.7.0.2
 * Multiple checkboxes for Job Specific Configuration and Global level configuration could get selected at a time for jenkins latest version 2.426.X. To avoid this discrepancy please hard refresh and re select one of the checkbox.
