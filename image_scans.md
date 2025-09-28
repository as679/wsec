# Image Scan Reports
## Summary

| Image                                                     | Vulnerability Counts                                |
| --------------------------------------------------------- | --------------------------------------------------- |
| wallarm/node-helpers:6.5.0                                | 2 critical, 25 high, 26 medium, 8 low, 0 negligible |
| wallarm/node-native-processing:0.18.0                     | 0 critical, 0 high, 1 medium, 6 low, 0 negligible   |
| wallarm/ingress-controller:6.5.1                          | 0 critical, 7 high, 11 medium, 6 low, 0 negligible  |
| registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.6.0 | 0 critical, 2 high, 1 medium, 0 low, 0 negligible   |

## Tooling
The tool used to scan the images is `grype` and is available [here](https://github.com/anchore/grype)

From the README.md file:
```text
A vulnerability scanner for container images and filesystems.
```

The version used is:
```text
$ grype version
Application:         grype
Version:             0.100.0
BuildDate:           2025-09-15T21:51:57Z
GitCommit:           088112b26e638c139a513f387f7a6e51f1a8b76d
GitDescription:      v0.100.0
Platform:            linux/amd64
GoVersion:           go1.24.7
Compiler:            gc
Syft Version:        v1.33.0
Supported DB Schema: 6
```

The output template is:
```shell
cat << EOF > tmpl
"Package","Version Installed","Vulnerability ID","Severity"
{{- range .Matches}}
"{{.Artifact.Name}}","{{.Artifact.Version}}","{{.Vulnerability.ID}}","{{.Vulnerability.Severity}}"
{{- end}}
EOF
```
## Reports
> **NOTE** All images are identified as per the documentation [here](https://docs.wallarm.com/)

### Native Node

**Command**
```shell
for image in $(helm template wallarm/wallarm-node-native | \
               yq .spec.template.spec.containers[].image | \
               grep -v '\-\-\-' | sort | uniq); do
  echo $image
  grype $image -o template -t tmpl | grep -i 'critical\|high'
done
```

**Image**
docker.io/wallarm/node-helpers:6.5.0
sha256:7f1cef6c670a693a2c2319d138b11b127adc0ce3599b910d52f006c4cd49e7af 

 ✔ Cataloged contents                                                                                                  9afb79fa4aec49a59de36e250a2eb6ded54f33ac3479f8fe5fbf94f9b5aba17a 
   ├── ✔ Packages                        [272 packages]  
   ├── ✔ Executables                     [490 executables]  
   ├── ✔ File metadata                   [302 locations]  
   └── ✔ File digests                    [302 files]  
 ✔ Scanned for vulnerabilities     [61 vulnerability matches]  
   ├── by severity: 2 critical, 25 high, 26 medium, 8 low, 0 negligible

**Output**
```text
"python","3.10.12","CVE-2024-6232","High"
"python","3.11.4","CVE-2024-6232","High"
"python","3.10.12","CVE-2024-4032","High"
"python","3.11.4","CVE-2024-4032","High"
"python","3.10.12","CVE-2024-7592","High"
"python","3.11.4","CVE-2024-7592","High"
"python","3.10.12","CVE-2024-0397","High"
"python","3.11.4","CVE-2024-0397","High"
"python","3.10.12","CVE-2025-4517","Critical"
"python","3.11.4","CVE-2025-4517","Critical"
"python","3.11.4","CVE-2023-41105","High"
"python","3.10.12","CVE-2025-4330","High"
"python","3.11.4","CVE-2025-4330","High"
"python","3.10.12","CVE-2024-8088","High"
"python","3.11.4","CVE-2024-8088","High"
"python","3.10.12","CVE-2025-4138","High"
"python","3.11.4","CVE-2025-4138","High"
"python","3.10.12","CVE-2025-8194","High"
"python","3.11.4","CVE-2025-8194","High"
"python","3.10.12","CVE-2023-6597","High"
"python","3.11.4","CVE-2023-6597","High"
"python","3.10.12","CVE-2023-36632","High"
"python","3.11.4","CVE-2023-36632","High"
"python","3.10.12","CVE-2025-4435","High"
"python","3.11.4","CVE-2025-4435","High"
"python","3.10.12","CVE-2024-9287","High"
"python","3.11.4","CVE-2024-9287","High"
```

**Image**
docker.io/wallarm/node-native-processing:0.18.0
 sha256:510eb911fb062983860607e8d0c35ea4f22c5dc56cb4dfbe4857259f6340cab4 
 
 ✔ Cataloged contents                                                                                                  7d57c98ba12caf77f0faf4f1371da7e81223d31232b1d4c23cd1c50a20d0384d 
   ├── ✔ Packages                        [156 packages]  
   ├── ✔ Executables                     [18 executables]  
   ├── ✔ File digests                    [83 files]  
   └── ✔ File metadata                   [83 locations]  
 ✔ Scanned for vulnerabilities     [7 vulnerability matches]  
   ├── by severity: 0 critical, 0 high, 1 medium, 6 low, 0 negligible

**Output**
```text
0 critical, 0 high
```

### NGINX Ingress Controller

**Command**
```shell
for image in $(helm template wallarm/wallarm-ingress | \
               yq .spec.template.spec.containers[].image | \
               grep -v '\-\-\-' | sort | uniq); do
  echo $image
  grype $image -o template -t tmpl | grep -i 'critical\|high'
done
```

**Image**
docker.io/wallarm/ingress-controller:6.5.1
 sha256:3fb66b41d89753a9e59c88373e9f2672f6b93907823c32d8bdab63f3b8df96a6
 
 ✔ Cataloged contents                                                                                                  d376db39212423173247650f085226a888e3b9614837666d311681db38e53a1f 
   ├── ✔ Packages                        [217 packages]  
   ├── ✔ Executables                     [231 executables]  
   ├── ✔ File metadata                   [789 locations]  
   └── ✔ File digests                    [789 files]  
 ✔ Scanned for vulnerabilities     [24 vulnerability matches]  
   ├── by severity: 0 critical, 7 high, 11 medium, 6 low, 0 negligible

**Output**
```text
"curl","8.14.1-r1","CVE-2025-9086","High"
"stdlib","go1.24.4","CVE-2025-47907","High"
"stdlib","go1.24.4","CVE-2025-47907","High"
"stdlib","go1.24.4","CVE-2025-47907","High"
"stdlib","go1.24.4","CVE-2025-4674","High"
"stdlib","go1.24.4","CVE-2025-4674","High"
"stdlib","go1.24.4","CVE-2025-4674","High"
```

**Image**
registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.6.0
sha256:c9f76a75fd00e975416ea1b73300efd413116de0de8570346ed90766c5b5cefb
 
 ✔ Cataloged contents                                                                                                  71be8d7dc903cd62c7ac49caad1165acfd7b9db0c2a33ee9660dfa4b2a03b4e2 
   ├── ✔ Packages                        [48 packages]  
   ├── ✔ Executables                     [1 executables]  
   ├── ✔ File metadata                   [942 locations]  
   └── ✔ File digests                    [942 files]  
 ✔ Scanned for vulnerabilities     [3 vulnerability matches]  
   ├── by severity: 0 critical, 2 high, 1 medium, 0 low, 0 negligible

**Output**
```text
"stdlib","go1.24.4","CVE-2025-47907","High"
"stdlib","go1.24.4","CVE-2025-4674","High"
```
