package com.qualys.plugins.containerSecurity.common.QualysClient;

class QualysAPIResponse {
    public int         responseCode;
    public boolean     errored;
    public String      errorMessage;

    public QualysAPIResponse() {
        responseCode = 0;
        errored = false;
        errorMessage = "";
    }
}
