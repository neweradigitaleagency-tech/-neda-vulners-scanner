package burp.tasks;

import burp.HttpClient;
import burp.Utils;
import burp.models.Vulnerability;
import burp.models.VulnersRequest;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

public class PathScanTask implements Runnable {

    private final HttpClient httpClient;
    private final Consumer<VulnersRequest> callback;
    private final VulnersRequest vulnersRequest;

    public PathScanTask(VulnersRequest vulnersRequest, HttpClient httpClient, Consumer<VulnersRequest> callback) {
        this.httpClient = httpClient;
        this.vulnersRequest = vulnersRequest;
        this.callback = callback;
    }

    @Override
    public void run() {
        List<String> paths = new ArrayList<>();
        paths.add(vulnersRequest.getPath());

        JSONObject data = httpClient.getVulnerablePathsV4(paths);

        Set<Vulnerability> vulnerabilities = Utils.getPathVulnerabilities(data);

        vulnersRequest.setVulnerabilities(vulnerabilities);
        callback.accept(vulnersRequest);
    }
}
