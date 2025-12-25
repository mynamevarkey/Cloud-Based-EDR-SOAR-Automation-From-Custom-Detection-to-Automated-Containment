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
![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/dg1.png)

## 🥇 Step 1: Virtual Machine Setup

A cloud-based virtual machine was provisioned using Vultr to serve as the endpoint environment for this lab. The instance was configured with Windows Client 2022 and completed using standard operating system initialization procedures. This virtual machine functioned as the primary test endpoint for sensor deployment, telemetry generation, and adversary simulation activities throughout the workflow.

![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/vm.png)


## 🥈 Step 2: LimaCharlie Sensor Deployment

A LimaCharlie account was created and a new sensor was generated from the platform. The sensor was downloaded and installed on the Windows client virtual machine. After successful deployment, the endpoint appeared in the LimaCharlie Overview section with full visibility into system details. The interface was then explored in depth, including sections for processes, network activity, services, and user context, to become familiar with the EDR capabilities and overall platform workflow.
![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/running.png)

## 🥉 Step 3: Adversary Tool Execution & Telemetry Observation

The LaZagne tool (`lazagne.exe`), a credential recovery utility, was executed on the Windows client while the LimaCharlie sensor was actively running. The tool was launched via PowerShell, allowing LimaCharlie to capture detailed process execution telemetry in real time. Upon execution, LimaCharlie generated a **New Process** event and transmitted the data to the LimaCharlie cloud console.
By reviewing the sensor’s timeline, the **New Process** event associated with LaZagne was identified and analyzed. Key metadata required for detection engineering was extracted from this event, including the executable file path, command-line arguments, and file hash. These indicators were later used to inform the creation of a custom detection and response rule.
![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/cmd.png)

Running LaZagne 

![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/detection.png)

Detection

## 🏅 Step 4: Building the Detection Rule

Rather than creating a rule entirely from scratch, an existing **Windows process creation** detection rule from LimaCharlie’s public GitHub repository was used as a baseline template. This approach ensured alignment with LimaCharlie’s recommended rule structure and reduced configuration errors.

A multi-layered detection rule was then authored to identify **LaZagne** execution using an **OR-based logic** across multiple indicators. The rule monitors both `NEW_PROCESS` and `EXISTING_PROCESS` events on Windows systems and evaluates several attributes, including executable file path, command-line arguments, parent process, and a known file hash. This layered approach increases detection reliability while reducing false positives.

Once the rule was deployed, `lazagne.exe` was executed again on the Windows endpoint. The activity successfully triggered the detection, and the alert appeared in the LimaCharlie detections console, confirming that the rule was functioning as intended.

### Detection Rule (YAML)

```yaml
detect:
  events:
    - NEW_PROCESS
    - EXISTING_PROCESS
  op: and
  rules:
    - op: is windows
    - op: or
      rules:
        - case sensitive: false
          op: ends with
          path: event/FILE_PATH
          value: lazagne.exe
        - case sensitive: false
          op: ends with
          path: event/COMMAND_LINE
          value: all
        - case sensitive: false
          op: contains
          path: event/COMMAND_LINE
          value: lazagne
        - case sensitive: false
          op: is
          path: event/HASH
          value: f7c237a49b96fd77c047910e13f24aac4678a0f94babdb06643dba63f38
        - case sensitive: false
          op: ends with
          path: event/PARENT/FILE_PATH
          value: lazagne.exe

response:
  - action: report
    metadata:
      author: wikki
      description: Detected LaZagne (SOAR–EDR Tool)
      falsepositives:
        - Unlikely
      level: medium
      tags:
        - attack.credential_access
    name: wikki - LaZagne (soar-edr)
```
Detections based on the rule specific 
![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/rule%20detection.png)

## 🏆 Step 5: SOAR Automation with Tines and Slack

For automation and incident response orchestration, **Tines** was used as the SOAR platform, with **Slack** integrated as the primary team communication channel. A dedicated Slack workspace and alert-specific channel were created to receive real-time security notifications. A corresponding workspace (Space) was then configured in Tines to implement the automation workflow.

The workflow is triggered whenever a password recovery tool or other malicious activity is detected on a client endpoint by LimaCharlie. Upon detection, the alert is forwarded to Tines via webhook, where the Story processes the event and notifies the SOC analyst through Slack and Email. The Slack notification includes an interactive decision point, allowing the analyst to determine whether the affected endpoint should be isolated.

Based on the analyst’s response:
- **If isolation is approved**, Tines issues an API request to LimaCharlie to isolate the endpoint and sends a confirmation message to the Slack alerts channel and Email.
- **If isolation is declined**, a notification is sent to the Slack alerts channel indicating that the system remains online and the case has been forwarded for further investigation.

![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/dig2.png)


### Slack Alert Messages

![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/alert1.png)


**Isolation Approved**

```text
Computer: <<webhook_action.body.detect.routing.hostname>>
The system has been isolated as a containment measure.
```
![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/true.png)

**Isolation Declined**

```
Computer: <<webhook_action.body.detect.routing.hostname>>
The system has not been isolated at this time. The case is being forwarded for investigation with caution ⚠️⚠️
```
![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/false.png)

***Email Alert***

![image alt](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/Email.png)


## 🏆 Step 6: Output

Before the SOC analyst approves isolation, the endpoint remains in its normal operational state. The detection is visible, but no containment action has been applied.

![Before Isolation](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/before%20.png)

After the analyst approves the isolation action through the SOAR workflow, the endpoint’s status changes to isolated. Network connectivity is restricted while EDR communication is maintained for investigation.

![After Isolation](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/after.png)

The following view confirms that the device has been successfully isolated, serving as verification that the automated containment action was executed correctly.

![Isolation Confirmation](https://github.com/mynamevarkey/Cloud-Based-EDR-SOAR-Automation-From-Custom-Detection-to-Automated-Containment/blob/main/machineisolation%20.png)


## ⚠️ Issues Faced

Several challenges were encountered during the implementation of this lab. Initial sensor deployment required careful verification to ensure the LimaCharlie agent was properly communicating with the cloud, as incomplete installation resulted in missing telemetry. Detection rule tuning was another challenge, particularly balancing sensitivity and accuracy—early rule versions generated noisy results until additional conditions were added to reduce false positives.

Webhook and API integration between LimaCharlie and Tines required precise payload parsing, as minor schema mismatches caused automation failures. Slack interactive actions also needed careful permission and token configuration to function correctly. Finally, testing isolation actions in a live environment required caution, as isolating the endpoint temporarily disrupted connectivity and delayed troubleshooting. These issues collectively reinforced the importance of incremental testing, validation, and rollback planning in security automation workflows.


## 📘 Lessons Learned

This lab reinforced the practical value of integrating EDR and SOAR platforms to move beyond isolated alerting and into actionable incident response. Designing custom detection rules highlighted the importance of leveraging multiple indicators—such as process paths, command-line arguments, and file hashes—to improve detection accuracy while minimizing false positives. 

Building automated workflows in Tines demonstrated how human-in-the-loop decision points can balance speed and control, enabling rapid containment without sacrificing analyst oversight. The exercise also emphasized the critical role of clear telemetry analysis, as understanding raw Windows endpoint events was essential for effective detection engineering. Overall, the lab underscored how well-designed automation, when paired with thoughtful detection logic, can significantly reduce Mean Time to Respond (MTTR) and improve SOC operational efficiency.

## 🚀 Next Steps

Future improvements to this lab will focus on expanding detection coverage and increasing automation maturity. Additional detection rules will be developed to cover a broader range of adversary techniques, including persistence, lateral movement, and command-and-control behaviors. Alert severity scoring and enrichment with external threat intelligence will be introduced to improve prioritization.

The SOAR workflow will be enhanced by adding automated evidence collection, case tracking, and escalation paths for high-confidence incidents. Further refinements will include automated rollback actions, post-incident reporting, and expanded notification integrations. Finally, the lab will be extended to support multiple endpoints and role-based analyst access to better simulate a production-scale SOC environment.

## ✅ Conclusion

This lab successfully demonstrated an end-to-end EDR and SOAR integration, transforming raw endpoint telemetry into automated, actionable incident response. By combining custom detection engineering in LimaCharlie with orchestration and human-in-the-loop decision-making in Tines, the workflow bridged the gap between threat detection and containment.

The implementation validated how layered detection logic, precise telemetry analysis, and controlled automation can significantly reduce Mean Time to Respond (MTTR) without removing analyst oversight. Overall, this project reflects a practical, production-aligned approach to modern SOC operations and highlights the effectiveness of automation when paired with well-engineered security detections.


