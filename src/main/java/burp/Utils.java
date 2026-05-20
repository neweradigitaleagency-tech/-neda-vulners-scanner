package burp;

import burp.models.PathVulnerability;
import burp.models.Vulnerability;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by vankyver on 05/07/2017.
 */
public class Utils {

    private Utils() {
    }

    public static Double getMaxScore(Set<Vulnerability> vulnerabilities) {
        if (vulnerabilities.size() <= 0) {
            return null;
        }

        return vulnerabilities.stream()
                .map(Vulnerability::getCvssScore)
                .max(Double::compareTo)
                .orElse(null);
    }

    public static Collection<String> getVulnersList(Set<Vulnerability> vulnerabilities) {
        if (vulnerabilities.size() <= 0) {
            return null;
        }

        return vulnerabilities.stream()
                .map(Vulnerability::getItemLink)
                .collect(Collectors.toList());
    }

    public static Set<Vulnerability> getPathVulnerabilities(JSONObject data) {
        Set<Vulnerability> vulnerabilities=new HashSet<>();
        // Use new API V4
        if(!data.has("result") || !data.get("result").getClass().equals(JSONObject.class))
            return new HashSet<>();
        data = data.getJSONObject("result");
        for (String path : data.keySet() ) {
            JSONArray vulns = data.getJSONArray(path);
            vulns.forEach(v -> {
                vulnerabilities.add(PathVulnerability.fromWebVulns(path, (JSONObject) v));
            });
        }

        return vulnerabilities;
    }


    public static Set<Vulnerability> getVulnerabilities(JSONObject data) {
        Set<Vulnerability> vulnerabilities = new HashSet<>();
        Map<String, Vulnerability> lVulnerabilities = new HashMap<>();

        // Use new API V4
        if(!data.has("result") || !data.get("result").getClass().equals(JSONArray.class))
            return vulnerabilities;

        String cveId;
        for (Object entry : data.getJSONArray("result") ) {
            for (Object vuln: ((JSONObject) entry).getJSONArray("vulnerabilities")) {
                cveId = ((JSONObject) vuln).getString("id");
                lVulnerabilities.put(cveId, Vulnerability.fromAuditV4((JSONObject) vuln));
            }
        }

        vulnerabilities.addAll(lVulnerabilities.values());

        return vulnerabilities;
    }

}
