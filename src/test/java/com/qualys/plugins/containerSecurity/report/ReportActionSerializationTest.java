package com.qualys.plugins.containerSecurity.report;

import static org.junit.Assert.assertNotNull;

import hudson.model.FreeStyleProject;
import hudson.model.FreeStyleBuild;
import com.google.gson.JsonObject;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.lang.reflect.Field;

public class ReportActionSerializationTest {
    @Rule public JenkinsRule j = new JenkinsRule();

    @Test
    public void runSaveWithPopulatedReportActionDoesNotThrow() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        FreeStyleBuild build = j.buildAndAssertSuccess(project);
        
        ReportAction action = new ReportAction();
        JsonObject sample = new JsonObject();
        sample.addProperty("imageId", "test-image");

        setField(action, "reportObject", sample);
        setField(action, "trendingData", sample);

        build.addAction(action);
        build.save();

        ReportAction restored = build.getAction(ReportAction.class);
        assertNotNull("ReportAction should be retrievable after save", restored);
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }
}
