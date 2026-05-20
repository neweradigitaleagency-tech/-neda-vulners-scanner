package burp.tasks;

import burp.Utils;
import burp.HttpClient;
import burp.models.VulnersRequest;
import burp.models.Software;
import burp.models.Vulnerability;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class SoftwareScanTask implements Runnable {

    private final HttpClient httpClient;
    private final Consumer<VulnersRequest> callback;
    private final VulnersRequest vulnersRequest;

    public SoftwareScanTask(VulnersRequest vulnersRequest, HttpClient httpClient, Consumer<VulnersRequest> callback) {
        this.httpClient = httpClient;
        this.vulnersRequest = vulnersRequest;
        this.callback = callback;
    }

    @Override
    public void run() {
        Software software = vulnersRequest.getSoftware();

        Map<String, String> params = new HashMap<>();
        params.put("software", software.getAlias());
        params.put("version", software.getVersion());
        params.put("type", software.getMatchType());
        JSONObject data = httpClient.getVulnerableSoftware(params);

        Set<Vulnerability> vulnerabilities = Utils.getVulnerabilities(data);

        vulnersRequest.setVulnerabilities(vulnerabilities);
        callback.accept(vulnersRequest);
    }
}
