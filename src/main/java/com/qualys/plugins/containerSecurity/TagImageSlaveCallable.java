package com.qualys.plugins.containerSecurity;

import java.io.IOException;
import java.io.Serializable;

import com.github.dockerjava.api.DockerClient;
import com.qualys.plugins.containerSecurity.util.DockerClientHelper;
import com.qualys.plugins.containerSecurity.util.Helper;

import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class TagImageSlaveCallable extends MasterToSlaveCallable<String, IOException> implements Serializable{
	private static final long serialVersionUID = -4143159957567745621L;
	private String image;
	private String imageId;
	private String dockerUrl;
	private String dockerCert;
	private TaskListener listener;
	private Helper helper;
	
	public TagImageSlaveCallable(Helper helper, String image, String imageId, String dockerUrl, String dockerCert, TaskListener listener) {
		this.helper = helper;
		this.image = image;
		this.imageId = imageId;
		this.dockerUrl = dockerUrl;
		this.dockerCert = dockerCert;
		this.listener = listener;
	}
	
	public String call() throws IOException {
		DockerClientHelper helper = new DockerClientHelper(listener.getLogger());
		DockerClient dockerClient = helper.getDockerClient(dockerUrl, dockerCert);
		helper.tagTheImage(this.helper, dockerClient, image, imageId);
		return "";
	}
}