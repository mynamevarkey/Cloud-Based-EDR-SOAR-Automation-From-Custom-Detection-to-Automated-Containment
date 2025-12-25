# Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment

## Objective
The primary objective of this project is to build a functional Automated Incident Response Pipeline that connects endpoint detection with automated remediation. By integrating LimaCharlie EDR and Tines SOAR, the project aims to replace manual security tasks with automated workflows—specifically detecting unauthorized password recovery tools and enabling one-click host isolation. Ultimately, the goal is to gain hands-on experience in reducing response times (MTTR) and mastering the logic required to design professional security playbooks.

## Highlights

- **Integrated EDR and SOAR Platforms**
  - Connected LimaCharlie EDR with Tines to create an automated detection-to-response pipeline.

- **Custom Detection Engineering**
  - Authored and deployed custom Detection & Response (D&R) rules in LimaCharlie to identify adversary tools, including password recovery software.

- **Automated Playbook Development**
  - Designed and built a Tines Story to orchestrate incident response workflows with Slack and Email notifications.

- **Dynamic Threat Containment**
  - Implemented one-click host isolation through SOAR-driven response actions, significantly reducing Mean Time to Respond (MTTR).

- **End-to-End Security Workflow**
  - Executed and documented a full lifecycle workflow from Windows endpoint telemetry generation to automated containment and remediation.

## Skills Learned

- **SOAR Workflow Engineering**
  - Designed automated security playbooks using Tines Stories, implementing trigger-action logic and multi-branch decision trees.

- **EDR Detection & Response (D&R)**
  - Wrote custom YAML-based detection rules in LimaCharlie to identify malicious behaviors, including credential-harvesting tools.

- **API & Webhook Integration**
  - Integrated security platforms (LimaCharlie, Tines, Slack) using API keys, webhooks, and REST API calls for cross-tool automation.

- **Incident Response Automation**
  - Implemented human-in-the-loop automation to accelerate containment actions, including automated host isolation to reduce MTTR.

- **Endpoint Telemetry Analysis**
  - Analyzed raw Windows endpoint telemetry to differentiate legitimate administrative activity from adversary behavior.

- **Logic-Based Problem Solving**
  - Translated manual SOC procedures into repeatable automated workflows using logic-driven process mapping and diagrams.

## 🛠️ Tools Used

- **LimaCharlie (EDR)**
  - Used as the primary Endpoint Detection and Response platform for real-time telemetry ingestion, custom detection rule creation, and executing response actions such as host isolation.

- **Tines (SOAR)**
  - Employed as the Security Orchestration, Automation, and Response platform to build automated playbooks (Stories) connecting detection events to remediation actions.

- **Windows Virtual Machine**
  - Served as the endpoint agent to generate telemetry and simulate a real-world Windows workstation environment.

- **Slack**
  - Integrated as the alerting and response interface, delivering real-time notifications and enabling interactive analyst approval for containment actions.

- **Email (SMTP)**
  - Configured as a secondary notification channel to ensure critical alerts reach stakeholders reliably.

- **LaZagne**
  - Used for adversary emulation to trigger process-based detections and validate the effectiveness of custom EDR rules.

## 🔄 Lab Workflow

- **Endpoint Activity & Telemetry Generation**
  - A Windows VM running the LimaCharlie sensor executes a password recovery tool (e.g., LaZagne), generating raw telemetry that is streamed in real time to the LimaCharlie cloud.

- **EDR Detection & Response (D&R) Rule**
  - A custom detection rule in LimaCharlie monitors for specific process executions or file artifacts associated with the tool. Upon a match, LimaCharlie generates a detection alert.

- **SOAR Integration (Detection-to-Response Bridge)**
  - The detection alert is forwarded to Tines via webhook. Tines ingests the JSON payload containing threat metadata, hostname, and user context.

- **Notification & Analyst Decision**
  - The Tines Story parses the alert data and sends simultaneous notifications to Slack and Email.  
  - The Slack alert includes an interactive prompt asking the analyst whether to isolate the affected endpoint.

- **Automated Remediation**
  - Upon analyst approval, Tines issues an API request to LimaCharlie to isolate the endpoint at the network level while maintaining EDR connectivity for investigation.

- **Verification & Closure**
  - A confirmation message is sent to Slack and Email, verifying successful host isolation and containment of the incident.

## Screenshots and Evidence

*Ref 1: Network Diagram*
![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/dig.png)

