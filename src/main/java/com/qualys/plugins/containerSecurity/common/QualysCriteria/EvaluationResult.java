package com.qualys.plugins.containerSecurity.common.QualysCriteria;



public class EvaluationResult {
    public String configured;
    public String found;
    public EvaluationResultValues result;

    public EvaluationResult() {
        this.configured = "";
        this.found = "";
        this.result = EvaluationResultValues.Pass;
    }
}
