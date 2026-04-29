package com.qualys.plugins.containerSecurity.common.QualysCriteria;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

@SuppressFBWarnings(value = "URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD", justification = "Fields may be used for serialization or future use")
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
