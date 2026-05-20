# neda-vulners-scanner

**Burp Suite** extension for vulnerability scanning using the [Vulners.com](https://vulners.com) API.

Scans HTTP responses for software version fingerprints and cross-references them against the Vulners vulnerability database. Also checks unique URL paths for known exploits.

## Features

- Fingerprint software versions from HTTP responses
- Look up CVEs, advisories, and exploits via Vulners API
- Check URL paths for known vulnerabilities
- Passive and active scanning modes
- Results integrated into Burp Suite dashboard

## Requirements

- Burp Suite Professional
- Java 17+
- Maven 3.6+

## Build

```bash
mvn clean package
```

Output: `target/neda-vulners-scanner-1.5.0.jar`

## Install

1. Open Burp Suite Professional
2. Go to **Extender** → **Add**
3. Select **Java** as extension type
4. Browse and select the built JAR
5. The scanner will appear in the Extender tab

## Usage

Once installed, the scanner runs automatically during Burp's active and passive scans. Detected vulnerabilities appear in the **Target** → **Site map** → **Issue activity** panel.

## License

LGPL-3.0
