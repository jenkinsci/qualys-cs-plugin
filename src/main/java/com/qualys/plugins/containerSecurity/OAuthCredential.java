package com.qualys.plugins.containerSecurity;

import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.Extension;
import hudson.util.FormValidation;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

public class OAuthCredential extends BaseStandardCredentials {

    private final String clientId;
    private final String clientSecret;


    @DataBoundConstructor
    public OAuthCredential(CredentialsScope scope, String id, String description,
                           String clientId, String clientSecret) {
        super(scope, id, description);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        public String getDisplayName() {
            return "OAuth Credential";
        }
        public FormValidation doCheckClientId(@QueryParameter String value) {
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Client ID cannot be empty");
            }
            return FormValidation.ok();
        }


        public FormValidation doCheckClientSecret(@QueryParameter String value) {
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("client Secret cannot be empty");
            }
            return FormValidation.ok();
        }
    }
}

