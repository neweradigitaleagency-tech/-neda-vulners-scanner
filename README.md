# neda-vulners-scanner

Burp Suite scanner plugin based on [Vulners.com](https://vulners.com) vulnerability database API
- Search fingerprints in http response and check found version in vulners.com vulnerability database
- Check unique URLs in vulners.com finding exploits for such paths

Detects vulnerable software and shows CVEs, advisories and exploits!

## Requirements

- Burp Suite - Professional Edition
- Java 17+
- Maven

## Build

```
mvn clean package
```

Output: `target/neda-vulners-scanner-1.5.0.jar`

## Install

Burp Suite Pro → Extender → Add → Java → select the JAR
