package com.qualys.plugins.containerSecurity.common.QualysClient;

import com.google.gson.JsonObject;

public class QualysCSResponse extends QualysAPIResponse {
    public JsonObject response;

    public QualysCSResponse() {
        super();
        response = null;
    }
}
