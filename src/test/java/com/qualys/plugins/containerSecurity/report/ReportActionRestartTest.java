package com.qualys.plugins.containerSecurity.report;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import hudson.model.FreeStyleProject;
import hudson.model.FreeStyleBuild;
import com.google.gson.JsonObject;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsSessionRule;

import java.lang.reflect.Field;

public class ReportActionRestartTest {
    @Rule
    public JenkinsSessionRule sessions = new JenkinsSessionRule();

    @Test
    public void reportActionSurvivesJenkinsRestart() throws Throwable {
        sessions.then(j -> {
            FreeStyleProject project = j.createFreeStyleProject("qualys-test");
            FreeStyleBuild build = j.buildAndAssertSuccess(project);

            ReportAction action = new ReportAction();
            JsonObject sample = new JsonObject();
            sample.addProperty("imageId","test-image");
            setField(action, "reportObject", sample);
            setField(action, "trendingData", sample);

            build.addAction(action);
            build.save();
        });

        sessions.then(j -> {
            FreeStyleProject project = (FreeStyleProject) j.jenkins.getItem("qualys-test");
            FreeStyleBuild build = project.getLastBuild();
            ReportAction action = build.getAction(ReportAction.class);

            assertNotNull("ReportAction should have been restored from build.xml after restart", action);

            Field reportObject = ReportAction.class.getDeclaredField("reportObject");
            reportObject.setAccessible(true);
            assertNull("transient field should be null after deserialization", reportObject.get(action));

            Field trendingData = ReportAction.class.getDeclaredField("trendingData");
            trendingData.setAccessible(true);
            assertNull("transient field should be null after deserialization", trendingData.get(action));
        });
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }
    
}
