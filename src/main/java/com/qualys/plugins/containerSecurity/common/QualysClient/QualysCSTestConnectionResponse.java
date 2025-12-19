package com.qualys.plugins.containerSecurity.common.QualysClient;

public class QualysCSTestConnectionResponse{
    public int responseCode;
    public boolean success;
    public String message;
    
    public QualysCSTestConnectionResponse(){
    	this.responseCode = 0;
    	this.success = false;
    	this.message = "";
    }
    
    public QualysCSTestConnectionResponse(int responseCode, boolean status, String message){
    	this.responseCode = responseCode;
    	this.success = status;
    	this.message = message;
    }
}