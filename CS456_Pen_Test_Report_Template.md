Penetration Test Report: \[Andrew (192.168.0.112)\]  
Author: \[Justin Marlor\]  
Date of Assessment: \[12/04/2025\]  
Version: 1.0

# **Executive Summary**
This penetration test was conducted to assess the security posture of the target virtual machine hosted at 192.168.0.112. The objective of the engagement was to simulate real-world adversarial behavior, identify vulnerabilities within the system’s containerized services, and evaluate the potential impact of successful exploitation.

During the assessment, multiple weaknesses were identified—most notably the presence of an outdated Apache Tomcat service accessible with default credentials. Although several exploitation attempts against the Tomcat Manager interface were unsuccessful due to version-specific limitations, the configuration itself represents a critical security risk.

Reconnaissance efforts revealed valuable information about the internal environment, including service versions, exposed management interfaces, and host configurations. The outdated Tomcat instance in particular dramatically reduces the overall security posture of the system. While no functional reverse shell was obtained during testing, this was due to exploit module mismatch rather than secure system hardening—meaning a determined attacker with the correct exploit chain could likely compromise the system fully.

Overall, the engagement demonstrates that the system is highly vulnerable, primarily due to legacy software, insecure default settings, and lack of proper hardening. Immediate remediation is required to prevent unauthorized access and potential system compromise.

## **Overview**

A penetration test was conducted against the target virtual machine to identify and assess security vulnerabilities within its containerized services. Through this assessment, vulnerabilities were discovered that led to the system being compromised. Documentation was collected of the penentration testing methods taken to gain access to the system and sensitive information.


### **High-Level Test Outcomes**

The penetration test was successful. During reconnaissance, sensitive user information was discovered, and administrative privileges were obtained on the web server. With this level of access, an attacker could potentially deploy a malicious WAR file or execute arbitrary commands, leading to full system compromise and possible access to the wider network.

### **Overall Risk Rating: CRITICAL**
  
The presence of an outdate web service in the system allows for many different possible exploitation attacks, which could lead to the entire network being compromised.

### **Prioritized Recommendations** {#prioritized-recommendations}

1. Immediately remove or update the vulnerable Apache Tomcat service, which allows attackers to gain admin level access by the leveraging of hardcoded credentials(CVE-2010-0557). 

# **Test Scope and Methodology** {#test-scope-and-methodology}

## **Scope** {#scope}

The scope of this penetration test was limited to the virtual machine and its services located at the following IP address:

* **In-Scope Target:** 192.168.1.112  
* **Out-of-Scope:** Any other devices on the network were explicitly out of scope. No denial-of-service (DoS) attacks were performed.

## **Methodology** {#methodology}

The assessment followed a standard penetration testing methodology. First, reconnaissance was performed using Nmap to identify open ports and running services. Next, vulnerabilities were identified in those services using automated scanners and manual analysis. Finally, the identified vulnerabilities were exploited to demonstrate impact.

# **Detailed Findings** {#detailed-findings}

![Nmap Scan](lab_screenshots/nmap_portscan.PNG)

The target IP was scanned from the msfconsole using the flags -sV and -Pn. These flags allowed us to send an aggressive scan that would bypass the firewall and discover open ports, as well as the services running on them. This scan collected extremely valuable knowledge about the host machine. From this scan I discovered three services running on open ports. The SSH and Postgresql services were running up to date versions, while the http service was running an outdated version with many known exploits.

**3.1. Finding 1: Default credentials**

* **Risk Rating:** Critical  
* **Description:** The containerized FTP service is running vsftpd version 2.3.4, which contains a known backdoor. By sending a specific string as the username during login, an attacker can trigger the backdoor and open a command shell on TCP port 6200 with root privileges.  
* **Affected Services/IPs:** 192.168.1.105 (TCP Port 21\)  
* Evidence (Proof of Concept): The following screenshot shows a successful connection to the backdoor shell using netcat and the execution of the id command, confirming root-level access:  
  \[Screenshot of terminal showing: nc 192.168.1.105 6200; id; uid=0(root) gid=0(root) groups=0(root)\]  
* **Remediation Steps:** The container image for the FTP service must be updated to a version of vsftpd that is not vulnerable (any version after 2.3.4). It is recommended to pull the latest official image for the service and redeploy the container.

# **Failed Exploit Attempts** {#failed-exploit-attempts}

### **MSF exploits for Tomcat**

![MSFexploits](<lab_screenshots/Apache Tomcat_MSF_search.PNG>)

![MSFexploits2](<lab_screenshots/Apache Tomcat_MSF_search.2.PNG>)

**4.1. Attempt 1 reverse TCP shell launch through mgr_deploy**

![mgr_deploy](<lab_screenshots/mgr_deploy_failure.PNG>)

* **Service Targeted:** Apache Tomcat web application on Port 8180
* **Description of Attempt:** This module deploys a WAR file to the Tomcat Manager through the text-based deployment API, allowing an attacker access to a terminal. 
* **Reason for Failure:** Deployment of upload file could not find correct path.

**4.2. Attempt 2 reverse TCP shell launch through jsp upload**

![jsp_upload](<lab_screenshots/jsp_upload_bypass_failure.PNG>)

* **Service Targeted:** Apache Tomcat web application on Port 8180 
* **Description of Attempt:** This exploit uploads a single malicious JSP file that will give access to a terminal through the webpage.
* **Reason for Failure:** Exploit was build for a different Tomcat version.

**4.3. Attempt 3 reverse TCP shell launch through mgr upload**

![mgr_upload](<lab_screenshots/tomcat_mgr_upload_failure.PNG>)

* **Service Targeted:** Apache Tomcat web application on Port 8180 
* **Description of Attempt:** This module uses tomcats webpage functionality to upload a WAR containing a webshell or meterpreter payload.
* **Reason for Failure:** failure to upload JSP file to the system.

# **Conclusions** {#conclusions}

The penetration test against the target machine demonstrated how outdated or improperly configured services can introduce severe security risks. While multiple exploitation attempts against Apache Tomcat were unsuccessful due to version incompatibilities and restricted upload mechanisms, reconnaissance efforts revealed significant weaknesses—including outdated software and the exposure of management interfaces. These issues, if combined with known exploits or credential leakage, could lead to full system compromise.

## **Summary of Attack Path** {#summary-of-attack-path}

![mgr_deploy](<lab_screenshots/DefaultCredential_LoginAttempt.PNG>)
![mgr_deploy](<lab_screenshots/Tomcat_Accessed.PNG>)

1. Reconnaissance (Nmap): An initial service scan identified several open ports—most notably an outdated Apache Tomcat web application running on port 8180. This discovery guided all subsequent exploitation attempts.

2. Service Enumeration: Examination of the Tomcat Manager interface indicated it was accessible but misconfigured, running a legacy version without modern security protections. Although valid credentials were available (tomcat:tomcat), the Manager’s upload paths were inconsistent with modern exploit modules.

3. Exploit Attempts:

mgr_deploy: Failed due to incorrect or unsupported deployment endpoints.

jsp_upload_bypass: Failed because the exploit module targeted a newer Tomcat architecture.

mgr_upload: Failed because the server did not support the WAR/JSP upload method expected by the module.

## **Overall Security Posture** {#overall-security-posture}

The target system’s overall security posture is poor and requires immediate remediation. The presence of an outdated Apache Tomcat instance, combined with default credentials, significantly increases the likelihood of compromise. Although exploitation attempts did not succeed in this assessment, they failed due to version mismatches rather than secure configuration. With the correct exploit modules or manual WAR package crafting, remote code execution remains highly feasible.

## **Tools Used** {#tools-used}

* Nmap  
* Metasploit Framework
