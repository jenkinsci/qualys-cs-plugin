package com.qualys.plugins.containerSecurity.util;

import java.io.PrintStream;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.google.gson.*;
import hudson.AbortException;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.scalasbt.ipcsocket.UnixDomainSocket;


import com.qualys.plugins.containerSecurity.httpClient.LocalDirectorySSLConfig;


public class DockerClientHelper {
	private final static Logger logger = Logger.getLogger(Helper.class.getName());
	private PrintStream buildLogger;
	
	private CloseableHttpClient httpClient = null;
	private String dockerURL;
	private String dockerCert;

	public DockerClientHelper() {
	}

	public DockerClientHelper(PrintStream buildLogger, String dockerURL, String dockerCert) {
		this.buildLogger = buildLogger;
		this.dockerURL = dockerURL;
		this.dockerCert = dockerCert;
	}

	private static String get(final String path) {
		return "GET " + path + " HTTP/1.1\r\n" + "Host: qualys\r\n" + "User-Agent: java-unix-socket-client/1.0\r\n"
				+ "Accept: application/json\r\n" + "\r\n";
	}

	private static String post(final String path) {
		return "POST " + path + " HTTP/1.1\r\n" + "Host: qualys\r\n" + "User-Agent: java-unix-socket-client/1.0\r\n"
				+ "Accept: application/json\r\n" + "\r\n";
	}

	public JsonObject executeSocketRequest(String method, String api) throws AbortException, IOException {
		JsonObject json_response = new JsonObject();
		String outputData = null;
		String apiResponseCode = "0";

		String dockerURL = this.dockerURL.replace("unix://", "");

		File f = new File(dockerURL);
		if (!f.exists()) {
			buildLogger.println("Socket file does not exist: " + dockerURL);
			throw new AbortException("Socket file does not exist: " + dockerURL);
		}

		final Socket socket = new UnixDomainSocket(dockerURL);

		try (final OutputStream os = socket.getOutputStream()) {
			if (method.toLowerCase().equals("get")) {
				os.write(get(api).getBytes(StandardCharsets.UTF_8));
			}
			if (method.toLowerCase().equals("post")) {
				os.write(post(api).getBytes(StandardCharsets.UTF_8));
			}

		} catch (Exception e) {
			socket.close();
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);

			buildLogger.println("API call failed using socket: " + e.getMessage());
			throw new AbortException("API call failed using socket: " + e.getMessage());
		}

		try (final BufferedReader response = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
			String line;
			long len = -1;
			while ((line = response.readLine()) != null) {
				if (line.toLowerCase().startsWith("content-length:")) {
					len = Long.parseLong(line.substring("content-length:".length()).trim());
					if (len == 0) {
						break;
					}
				} else if (line.startsWith("HTTP/1.1 ")) {
					apiResponseCode = line.split(" ")[1];
				} else if (line.toLowerCase().startsWith("{") || line.toLowerCase().startsWith("[")) {
					outputData = line;
					break;
				}
			}
		} catch (Exception e) {
			socket.close();
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\t Exception occurred at " + traceElement);

			buildLogger.println("Error reading response from socket: " + e.getMessage());
			throw new AbortException("Error reading response from socket: " + e.getMessage());
		}
		socket.close();
		
		json_response.addProperty("responseCode", apiResponseCode);
		if (outputData != null) {
			JsonElement jelement = JsonParser.parseString(outputData);
			if (jelement.isJsonObject()) {
				JsonObject jobject = jelement.getAsJsonObject();
				json_response.add("data", jobject);
			} else if (jelement.isJsonArray()) {
				JsonArray jarray = jelement.getAsJsonArray();
				json_response.add("data", jarray);
			}
		} else {
			json_response.addProperty("data", "");
		}
		return json_response;
	}

	public JsonObject executeHttpRequest(String action, String path) throws AbortException {
		JsonObject json_response = new JsonObject();
		Registry<ConnectionSocketFactory> socketFactoryRegistry = null;
		LocalDirectorySSLConfig sslConfig = null;
		HttpRequestBase request = null;

		if (!StringUtils.isEmpty(this.dockerCert)) {
			path = path.replace("http://", "https://");
			RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder = RegistryBuilder.create();
			String dockerCertPath = checkDockerCertPath(this.dockerCert);
			sslConfig = new LocalDirectorySSLConfig(dockerCertPath);

			if (sslConfig != null) {
				try {
					SSLContext sslContext = sslConfig.getSSLContext();
					if (sslContext != null) {
						socketFactoryRegistry = socketFactoryRegistryBuilder
								.register("https", new SSLConnectionSocketFactory(sslContext)).build();
					}
					else {
						throw new AbortException("Unable to find SSL Context");
					}
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}

			BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(
					socketFactoryRegistry);

			httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();

		} else {
			httpClient = HttpClients.custom().build();
		}

		try {
			HttpContext context = new BasicHttpContext();
			if (action.toLowerCase().equals("get")) {
				request = new HttpGet(URI.create(path));
			}
			if (action.toLowerCase().equals("post")) {
				request = new HttpPost(URI.create(path));
			}

			CloseableHttpResponse response = httpClient.execute(request, context);
			String outputData = EntityUtils.toString(response.getEntity());
			json_response.addProperty("responseCode", response.getStatusLine().getStatusCode());
			if (outputData != null) {
				JsonElement jelement = JsonParser.parseString(outputData);
				if (jelement.isJsonObject()) {
					JsonObject jobject = jelement.getAsJsonObject();
					json_response.add("data", jobject);
				} else if (jelement.isJsonArray()) {
					JsonArray jarray = jelement.getAsJsonArray();
					json_response.add("data", jarray);
				}
			} else {
				json_response.addProperty("data", "");
			}
		} catch (Exception e) 
		{
			if (e.getMessage() == null) {
				logger.info("Unable to execute http request, Please check Qualys credentials or docker configuration");
				throw new AbortException("Unable to execute http request, Please check Qualys credentials or docker configuration");
			} else {
				logger.info("Unable to execute http request, Msg: " + e.getMessage());
				throw new AbortException("Unable to execute http request, Msg: " + e.getMessage());
			}
		}
		return json_response;
	}

	public boolean tagImage(String imageIdOrName, String imageSha) throws AbortException, IOException {
		JsonObject api_response = null;
		String dockerURL = null;
		String api = "/images/" + imageIdOrName + "/tag?repo=qualys_scan_target&tag=" + imageSha;

		try {
			if (isUnixHostScheme()) {
				api_response = executeSocketRequest("POST", api);
			} else {
				dockerURL = this.dockerURL.replace("tcp://", "http://");
				api_response = executeHttpRequest("POST", dockerURL + api);

			}
			if (api_response.has("responseCode") && api_response.get("responseCode").getAsString().equals("201")) {
				buildLogger.println("Tagged image(" + imageIdOrName + ") successfully");
				return true;
			} else {
				throw new AbortException("API response code is not 201, Response Code: "
						+ api_response.get("responseCode").getAsString());
			}
		} catch (Exception e) {
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			buildLogger.println("Failed to tag the image " + imageIdOrName
					+ " with qualys_scan_target.. Reason : " + e.getMessage());
			throw new AbortException("Failed to tag the image " + imageIdOrName + " with qualys_scan_target.. Reason : "
					+ e.getMessage());
		}

	}

	public String fetchImageSha(String image, String dockerCert) throws AbortException {
		try {
			JsonObject api_response = null;
			String dockerURL = null;
			String api = "/images/" + image + "/json";
			if (isUnixHostScheme()) {
				api_response = executeSocketRequest("GET", api);
			} else {
				dockerURL = this.dockerURL.replace("tcp://", "http://");
				api_response = executeHttpRequest("GET", dockerURL + api);
			}

			if (api_response.has("responseCode") && api_response.get("responseCode").getAsString().equals("200")) {
				JsonObject json_response = JsonParser.parseString(api_response.get("data").toString())
						.getAsJsonObject();
				String imageId = json_response.get("Id").getAsString();
				String[] imageIds = imageId.split(":");
				String imageSha = imageIds[1];
				buildLogger.println("### Image sha for " + image + " is = " + imageSha);
				return imageSha;
			}
			throw new AbortException(api_response.get("data").getAsString());

		} catch (Exception e) {
			String errorMsg = "Failed to extract image sha associated with " + image + " ; Reason : " + e.getMessage();
			logger.info(errorMsg);
			throw new AbortException(errorMsg);
		}

	}

	@SuppressWarnings("unchecked")
	public boolean isCICDSensorUp() throws IOException, AbortException {
		JsonObject api_response = null;
		String dockerURL = null;
		if (isUnixHostScheme()) {
			api_response = executeSocketRequest("GET", "/containers/json");
		} else {
			dockerURL = this.dockerURL.replace("tcp://", "http://");
			api_response = executeHttpRequest("GET", dockerURL + "/containers/json");

		}
		if (api_response.get("responseCode").getAsString().equals("200")) {
			JsonArray containerArray = JsonParser.parseString(api_response.get("data").toString()).getAsJsonArray();

			for (JsonElement containerInnerData : containerArray) {
				JsonObject containerObj = containerInnerData.getAsJsonObject();
				String label = containerObj.get("Labels").toString();

				Gson gson = new Gson();
				Map<String, String> map = gson.fromJson(label, Map.class);
				if (map.containsKey("VersionInfo") && map.get("VersionInfo").contains("Qualys Sensor")) {
					if (containerObj.has("Id") && containerObj.get("Id").getAsString() != null
							&& !containerObj.get("Id").getAsString().isEmpty()) {
						String id = containerObj.get("Id").getAsString();
						String state = getContainerState(id);
						if (state != null && !state.isEmpty() && state.equals("paused")) {
							buildLogger.println("Sensor Container State - paused ");
							throw new AbortException(
									"Qualys CS sensor container is in paused state. Sensor won't be able to scan the image. Please check the sensor container.");
						}
						if (containerObj.has("Command") && containerObj.get("Command").getAsString() != null
								&& !containerObj.get("Command").getAsString().isEmpty()
								&& containerObj.get("Command").getAsString().contains("cicd-deployed-sensor")) {
							return true;
						}
					}

				}
			}

			throw new AbortException(
					"Qualys CS sensor container is not running... Please check if sensor is configured correctly.");

		}
		return false;
	}

	private String getContainerState(String id) throws IOException, AbortException {
		JsonObject api_response = null;
		String state = null;
		String dockerURL = null;

		if (isUnixHostScheme()) {
			api_response = executeSocketRequest("GET", "/containers/" + id + "/json");
		} else {
			dockerURL = this.dockerURL.replace("tcp://", "http://");
			api_response = executeHttpRequest("GET", dockerURL + "/containers/" + id + "/json");
		}
		if (api_response.get("responseCode").getAsString().equals("200")) {
			JsonObject json_response = JsonParser.parseString(api_response.get("data").toString()).getAsJsonObject();
			JsonObject stateObject = json_response.get("State").getAsJsonObject();
			state = stateObject.has("Status") ? stateObject.get("Status").getAsString() : "";
		}
		return state;
	}

	private boolean isUnixHostScheme() {
		return this.dockerURL.startsWith("unix://") ? true : false;
	}

	private String checkDockerCertPath(String dockerCertPath) throws AbortException {
		File certPath = new File(dockerCertPath);

		if (!certPath.exists()) {
			buildLogger.println("Docker Cert File Path does not exist");
			throw new AbortException("Docker Cert File Path " + dockerCertPath + "' doesn't exist.");
		} else if (!certPath.isDirectory()) {
			throw new AbortException("Docker Cert File Path " + dockerCertPath + "' doesn't point to a directory.");
		}
		return dockerCertPath;
	}

}