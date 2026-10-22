package com.csl.helpdesk;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public final class JiraClientTest {
    private static int checks;
    private static void check(boolean value) {
        if (!value) throw new AssertionError("Check " + (checks + 1) + " failed");
        checks++;
    }
    private static final class Fake extends HttpURLConnection {
        int status = 200;
        String type = "application/json;charset=UTF-8";
        boolean disconnected;
        byte[] body = "{\"name\":\"test\"}".getBytes(StandardCharsets.UTF_8);
        Fake() throws Exception { super(new URL("https://jira.example")); }
        public void connect() {}
        public void disconnect() { disconnected = true; }
        public boolean usingProxy() { return false; }
        public int getResponseCode() { return status; }
        public String getContentType() { return type; }
        public InputStream getInputStream() { return new ByteArrayInputStream(body); }
    }
    public static void main(String[] args) throws Exception {
        check(JiraClient.serverUrl("https://jira.example/jira/").equals("https://jira.example/jira"));
        for (String bad : new String[]{"http://jira.example", "https://a:b@jira.example", "https://jira.example?x=1", "https://jira.example/#foo", "https://"}) {
            try { JiraClient.serverUrl(bad); throw new AssertionError(bad); }
            catch (IllegalArgumentException expected) { checks++; }
        }
        Fake good = new Fake();
        JiraClient client = new JiraClient(url -> {
            check(url.toString().equals("https://jira.example/jira/rest/api/2/myself"));
            return good;
        });
        check(client.get("https://jira.example/jira", "Basic dGVzdDpzZWNyZXQ=", "myself").contains("test"));
        check(good.getRequestProperty("Authorization").equals("Basic dGVzdDpzZWNyZXQ="));
        check(!good.getInstanceFollowRedirects());
        check(good.getConnectTimeout() == 15000 && good.getReadTimeout() == 20000);
        check(good.disconnected);
        for (int status : new int[]{301,302,401,403,404,410,429,500}) {
            Fake failed = new Fake(); failed.status = status;
            try { new JiraClient(url -> failed).get("https://jira.example", "Basic test", "myself"); throw new AssertionError(); }
            catch (JiraClient.Failure expected) { check(expected.getMessage().contains(Integer.toString(status))); }
            check(failed.disconnected);
        }
        Fake html = new Fake(); html.type = "text/html";
        try { new JiraClient(url -> html).get("https://jira.example", "Basic test", "myself"); throw new AssertionError(); }
        catch (JiraClient.Failure expected) { check(expected.getMessage().contains("JSON")); }
        check(html.disconnected);
        Fake large = new Fake(); large.body = new byte[4 * 1024 * 1024 + 1];
        try { new JiraClient(url -> large).get("https://jira.example", "Basic test", "myself"); throw new AssertionError(); }
        catch (JiraClient.Failure expected) { check(expected.getMessage().contains("4 MiB")); }
        check(large.disconnected);
        try { client.get("https://jira.example", "Basic x\r\nBad: y", "myself"); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { checks++; }
        try { client.get("https://jira.example", "Basic test", "https://evil.example"); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { checks++; }
        Fake search = new Fake();
        new JiraClient(url -> { check(url.getPath().equals("/rest/api/2/search")); return search; }).get(
            "https://jira.example", "Basic test", "search?startAt=100&maxResults=100&fields=summary,description,status,priority,assignee,reporter,created");
        check(search.disconnected);
        System.out.println("PASS: JiraClient " + checks + " assertions (fake transport, no real Jira server)");
    }
}
