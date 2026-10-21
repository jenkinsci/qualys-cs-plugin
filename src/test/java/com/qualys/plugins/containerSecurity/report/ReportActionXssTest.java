package com.qualys.plugins.containerSecurity.report;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlPage;
import org.junit.Test;

public class ReportActionXssTest {
    private static final String XSS_PAYLOAD = "<img id=qualys-xss-marker src=x>";

    @Test
    public void reportTreatsConfiguredCriteriaAsText() throws Exception {
        String jquery = Files.readString(
                Path.of("src/main/webapp/js/jquery-3.5.0.min.js"), StandardCharsets.UTF_8);
        String reportScript = Files.readString(
                Path.of("src/main/webapp/js/report.js"), StandardCharsets.UTF_8);

        try (WebClient webClient = new WebClient()) {
            webClient.getOptions().setThrowExceptionOnScriptError(false);
            HtmlPage page = webClient.loadHtmlCodeIntoCurrentWindow(testPage(jquery, reportScript));
            page.executeJavaScript("drawSummaryTable(" + createReport() + ");");

            assertNull("configured criteria must not create HTML elements", page.getElementById("qualys-xss-marker"));
            assertContainsPayload(page, "#qid-found .tooltip-text");
            assertContainsPayload(page, "#cve-found .tooltip-text");
            assertContainsPayload(page, "#software-found .tooltip-text");
            assertContainsPayload(page, "#excluded-items");
        }
    }

    @Test
    public void reportDataIsNotInterpolatedIntoJavaScript() throws Exception {
        String jelly = Files.readString(
                Path.of("src/main/resources/com/qualys/plugins/containerSecurity/report/ReportAction/index.jelly"),
                StandardCharsets.UTF_8);
        int scriptStart = jelly.lastIndexOf("<script>");
        int scriptEnd = jelly.indexOf("</script>", scriptStart);
        String inlineScript = jelly.substring(scriptStart, scriptEnd);

        assertTrue(jelly.contains("data-report-object=\"${it.reportJsonObject}\""));
        assertTrue(jelly.contains("data-image-name=\"${it.imageNameOrImageId}\""));
        assertFalse("server values must stay out of executable JavaScript", inlineScript.contains("${it."));
    }

    @Test
    public void vulnerabilityDetailsTreatReportFieldsAsText() throws Exception {
        String jquery = Files.readString(
                Path.of("src/main/webapp/js/jquery-3.5.0.min.js"), StandardCharsets.UTF_8);
        String reportScript = Files.readString(
                Path.of("src/main/webapp/js/report.js"), StandardCharsets.UTF_8);

        try (WebClient webClient = new WebClient()) {
            HtmlPage page = webClient.loadHtmlCodeIntoCurrentWindow(testPage(jquery, reportScript));
            page.executeJavaScript("jQuery('body').append(format(" + vulnerabilityDetails() + "));");

            assertNull("scan report fields must not create HTML elements", page.getElementById("qualys-xss-marker"));
            assertTrue("scan report fields should still be displayed", page.getBody().asNormalizedText().contains(XSS_PAYLOAD));
        }
    }

    @Test
    public void dataTableRendererEscapesDisplayValues() throws Exception {
        String jquery = Files.readString(
                Path.of("src/main/webapp/js/jquery-3.5.0.min.js"), StandardCharsets.UTF_8);
        String reportScript = Files.readString(
                Path.of("src/main/webapp/js/report.js"), StandardCharsets.UTF_8);

        try (WebClient webClient = new WebClient()) {
            HtmlPage page = webClient.loadHtmlCodeIntoCurrentWindow(testPage(jquery, reportScript));
            page.executeJavaScript(
                    "jQuery('body').append('<div id=rendered-value>' + renderText(" + payloadJson() + ", 'display') + '</div>');");

            assertNull("table display values must not create HTML elements", page.getElementById("qualys-xss-marker"));
            assertTrue("table display values should still be displayed",
                    page.getElementById("rendered-value").asNormalizedText().contains(XSS_PAYLOAD));
        }
    }

    @Test
    public void dataTablesEscapeHiddenColumnValues() throws Exception {
        String jquery = Files.readString(
                Path.of("src/main/webapp/js/jquery-3.5.0.min.js"), StandardCharsets.UTF_8);
        String dataTables = Files.readString(
                Path.of("src/main/webapp/datatable/js/jquery.dataTables.min.js"), StandardCharsets.UTF_8);
        String reportScript = Files.readString(
                Path.of("src/main/webapp/js/report.js"), StandardCharsets.UTF_8);

        try (WebClient webClient = new WebClient()) {
            HtmlPage page = webClient.loadHtmlCodeIntoCurrentWindow(dataTablePage(jquery, dataTables, reportScript));
            page.executeJavaScript("drawTables(" + dataTableReport() + ");"
                    + "var softwareTable = jQuery('#softwareTable').DataTable();"
                    + "var cells = softwareTable.cells().nodes().toArray();"
                    + "var injected = cells.some(function(cell) { return cell.querySelector('#qualys-xss-marker'); });"
                    + "document.body.setAttribute('data-hidden-column-injection', String(injected));"
                    + "document.body.setAttribute('data-unpatchable', String(softwareTable.cell(0, 5).render('filter')));"
                    + "document.body.setAttribute('data-patchable', String(softwareTable.cell(1, 5).render('filter')));");

            assertTrue("hidden table cells must not parse report values as HTML",
                    "false".equals(page.getBody().getAttribute("data-hidden-column-injection")));
            assertEquals("false", page.getBody().getAttribute("data-unpatchable"));
            assertEquals("true", page.getBody().getAttribute("data-patchable"));
        }
    }

    private static void assertContainsPayload(HtmlPage page, String selector) {
        HtmlElement element = page.querySelector(selector);
        assertTrue("configured criteria should still be displayed", element.asNormalizedText().contains(XSS_PAYLOAD));
    }

    private static String testPage(String jquery, String reportScript) {
        StringBuilder body = new StringBuilder();
        body.append("<div id='qid-found'><div class='image-scan-status'><span class='tooltip-text'></span></div></div>");
        body.append("<div id='cve-found'><div class='image-scan-status'><span class='tooltip-text'></span></div></div>");
        body.append("<div id='cvss-found'><div class='image-scan-status'><span class='tooltip-text'></span></div></div>");
        body.append("<div id='software-found'><div class='image-scan-status'><span class='tooltip-text'></span></div></div>");
        for (int severity = 1; severity <= 5; severity++) {
            body.append("<div id='sev")
                    .append(severity)
                    .append("-found'><div class='image-scan-status'><span class='tooltip-text'></span></div></div>");
        }
        body.append("<div id='excluded-items'></div><div id='potential-checked'></div>");
        return "<!doctype html><html><body>" + body + "<script>" + jquery + "</script><script>" + reportScript
                + "</script></body></html>";
    }

    private static String dataTablePage(String jquery, String dataTables, String reportScript) {
        return "<!doctype html><html><body>"
                + "<div id='layers'></div><div class='left-pill-item layers'></div>"
                + "<table id='softwareTable'></table><table id='layersTable'></table><table id='vulnsTable'></table>"
                + "<div class='softwares-custom-filters'></div><div class='custom-filters'></div>"
                + "<div class='custom-filters-left'></div>"
                + "<script>"
                + jquery
                + "</script><script>"
                + dataTables
                + "</script><script>"
                + reportScript
                + "</script></body></html>";
    }

    private static JsonObject createReport() {
        JsonObject report = new JsonObject();
        JsonObject qids = criteria(XSS_PAYLOAD);
        qids.addProperty("excluded", XSS_PAYLOAD);
        report.add("qids", qids);
        report.add("cveIds", criteria(XSS_PAYLOAD));

        JsonObject cvss = criteria("");
        cvss.addProperty("configured", -1);
        cvss.addProperty("version", "3");
        report.add("cvss", cvss);
        report.add("software", criteria(XSS_PAYLOAD));

        JsonObject severities = new JsonObject();
        for (int severity = 1; severity <= 5; severity++) {
            JsonObject value = new JsonObject();
            value.add("configured", null);
            severities.add(Integer.toString(severity), value);
        }
        report.add("severities", severities);
        report.addProperty("potentialVulnsChecked", false);
        return report;
    }

    private static JsonObject criteria(String configured) {
        JsonObject criteria = new JsonObject();
        criteria.addProperty("configured", configured);
        criteria.addProperty("found", "");
        criteria.addProperty("result", true);
        criteria.addProperty("excluded", "");
        return criteria;
    }

    private static JsonObject vulnerabilityDetails() {
        JsonObject cvssInfo = new JsonObject();
        cvssInfo.addProperty("baseScore", XSS_PAYLOAD);
        cvssInfo.addProperty("temporalScore", XSS_PAYLOAD);
        cvssInfo.addProperty("accessVector", XSS_PAYLOAD);

        JsonObject cvss3Info = new JsonObject();
        cvss3Info.addProperty("baseScore", XSS_PAYLOAD);
        cvss3Info.addProperty("temporalScore", XSS_PAYLOAD);

        JsonObject details = new JsonObject();
        details.add("cvssInfo", cvssInfo);
        details.add("cvss3Info", cvss3Info);
        details.addProperty("cveids", XSS_PAYLOAD);
        details.addProperty("result", XSS_PAYLOAD);
        return details;
    }

    private static JsonObject dataTableReport() {
        JsonObject vulnerability = new JsonObject();
        vulnerability.addProperty("qid", XSS_PAYLOAD);
        JsonArray vulnerabilities = new JsonArray();
        vulnerabilities.add(vulnerability);

        JsonObject software = new JsonObject();
        software.addProperty("name", "example");
        software.addProperty("version", "1.0");
        software.addProperty("fixVersion", "");
        software.add("vulnerabilities", vulnerabilities);
        JsonArray softwareRows = new JsonArray();
        softwareRows.add(software);
        JsonObject patchableSoftware = software.deepCopy();
        patchableSoftware.addProperty("name", "patchable-example");
        patchableSoftware.addProperty("fixVersion", "1.1");
        softwareRows.add(patchableSoftware);

        JsonObject report = new JsonObject();
        report.add("softwaresTable", softwareRows);
        report.add("layersTable", new JsonArray());
        report.add("vulnsTable", new JsonArray());
        return report;
    }

    private static String payloadJson() {
        return new com.google.gson.Gson().toJson(XSS_PAYLOAD);
    }
}
