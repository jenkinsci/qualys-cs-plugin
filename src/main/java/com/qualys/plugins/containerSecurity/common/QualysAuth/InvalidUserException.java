package com.qualys.plugins.containerSecurity.common.QualysAuth;

class InvalidUserException extends Exception {
    @Override
    public String toString() {
        return "Invalid User";
    }
}
