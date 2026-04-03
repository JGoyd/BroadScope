# Threat Model: BroadScope (BCM4387 Autonomous Promiscuous Capture)

## Overview

This threat model analyzes the capabilities demonstrated by the **BroadScope** vulnerability in the Broadcom BCM4387C2 Wi‑Fi/Bluetooth SoC, focusing on attack vectors, threat actor motivations, and potential impact scenarios. Evidence from the forensic analysis (RAM dump and Bluetooth HCI logs) indicates capabilities consistent with a wireless propagation mechanism operating below the visibility of the host operating system.

## 1. Threat Actors & Motivations

### Likely Threat Actors
- **State‑sponsored actors**: Seeking persistent, low‑visibility access for intelligence gathering or surveillance.
- **Cybercriminal groups**: Interested in credential theft, financial fraud, or ransomware deployment.
- **Advanced persistent threats (APTs)**: Requiring foothold establishment for lateral movement within networks.

### Primary Motivations
- **Credential harvesting**: Capture of unencrypted or weakly encrypted credentials from network traffic (e.g., via observed DNS/HTTPS capture).
- **Network reconnaissance**: Mapping of internal networks, services, and device inventories (supported by promiscuous mode capture of mDNS/Bonjour traffic).
- **Supply chain compromise**: Targeting devices for subsequent enterprise infiltration.
- **Surveillance**: Long‑term monitoring of specific targets or geographic areas.

## 2. Attack Surface & Vectors

### Vulnerable Components
- **BCM4387C2 Wi‑Fi/Bluetooth SoC**: Present in iPhone 12‑15 series, compatible iPad models (iPad Air 2020+), and select MacBook models (M1 Pro, M2 Air, etc.).
- **DBPP (D11 Backplane Patch/Program) mechanism**: Runtime function patching without integrity verification (as evidenced by the patch table at offset 0x0000F0 in SoC_RAM.bin).
- **Shared radio resources**: Wi‑Fi and Bluetooth subsystems coexisting on the same silicon, managed by a coexistence arbiter (whose handler functions are patched to writable RAM, per offsets 0x0001C0 and 0x0001D8).

### Initial Compromise Vectors (Hypothetical)
While this report documents observed exploitation, initial compromise could occur via:
1. **Over‑the‑air exploit**: Leveraging parsing vulnerabilities in Wi‑Fi firmware (similar to Broadpwn CVE‑2017‑11120).
2. **Supply chain compromise**: Malicious firmware updates.
3. **Physical access**: JTAG/debug interface exploitation.
4. **Host‑to‑firmware**: Exploiting PCIe interface vulnerabilities.

## 3. Capabilities Analysis

### Demonstrated Capabilities (From Evidence in VULNERABILITY_REPORT.md)
| Capability | Evidence Offset | Security Implication |
|------------|----------------|----------------------|
| Promiscuous mode activation | 0x19DCCF et al. | Full‑spectrum traffic capture (register value `0x3f80028`). |
| Foreign frame retention | 0x149B28 et al. | Cross‑subnet data collection (packets to MAC 26:a9:9a:51:15:4a/IP 172.17.177.253). |
| Host command absence | Gap 0x19DB3B→0x19DCCF | Autonomous operation (23.087s with zero host SET commands). |
| Coex arbiter patching | 0x0001C0, 0x0001D8 | Inter‑processor subversion (wlc_coex_handler/wlc_coex_notify redirected to RAM). |
| PCIe function patching | 0x000154‑0x0002E0 | Host obfuscation (all 7 PCIe host interface functions patched). |
| Security function patching | (various) | MIC validation bypass (wlc_security_check_mic, wlc_security_decrypt patched). |
| Module loading | 0x1BB620, 0x1BBE30 | Monitor/pkt_filter infrastructure loaded. |

### Propagation‑Relevant Capabilities
The following capabilities suggest worm‑like propagation potential:

#### Reconnaissance Phase
- **Promiscuous mode capture**: Observed collection of DNS/HTTPS/mDNS traffic for target fingerprinting.
- **Target fingerprinting**: Ability to identify device types, iOS version, services (from captured DNS/HTTPS).
- **Network mapping**: Discovery of adjacent subnets and devices (via foreign subnet packet retention).

#### Delivery Mechanisms
- **Raw 802.11 frame injection**: Patched `wlc_d11_raw_tx` enables arbitrary frame construction (essential for payload delivery).
- **AWDL vector**: Apple Wireless Direct Link provides peer‑to‑peer channel (observed AWDL activity on wl0.2 in the RAM dump).
- **Bluetooth LE**: Autonomous connection attempts observed in HCI logs (23 LE Enhanced Connection Complete events with status 0x02 to 00:00:00:00:00:00).

#### Target Neutralization
- **MIC validation bypass**: Patched `wlc_security_check_mic` reduces validation barriers on target devices.
- **Pre‑MIC exploit delivery**: Ability to deliver frames triggering parsing vulnerabilities *before* MIC validation.
- **No requirement to pass MIC**: Exploit can trigger vulns in target firmware parsing without needing to bypass MIC.

#### Persistence Mechanisms
- **DBPP patch table modification**: Write new entries to redirect critical functions (e.g., wlc_d11_raw_tx, wlc_security_check_mic) to attacker‑controlled code.
- **RAM residency**: Persists until device reboot.
- **Potential firmware modification**: If flash/NVRAM accessible, survives reboot (though not observed in the analyzed dump).

## 4. Attack Flow & Propagation Lifecycle

### Hypothetical Worm Propagation Model
Based on observed evidence and capability analysis:

```
PHASE 1: RECON
    → Activate promiscuous mode (6.4s windows, as seen in event log)
    → Capture DNS/HTTPS/mDNS from nearby devices
    → Fingerprint targets (device type, iOS version, services)
    → Channel‑hop to maximize discovery
    → Deactivate to minimize RF footprint

PHASE 2: TARGET SELECTION
    → Identify vulnerable targets (same iOS version, missing patches)
    → Prioritize high‑value targets (enterprise credentials, sensitive data)
    → Map network topology and trust relationships

PHASE 3: DELIVERY
    → Craft exploit payload (targeting Wi‑Fi firmware parser vuln)
    → Encode in AWDL or management frame
    → Transmit via patched wlc_d11_raw_tx (raw 802.11 injection)
    → Alternative: Attempt BLE connection for proximity delivery

PHASE 4: EXECUTION
    → Target's BCM4387 parses malicious frame
    → Vulnerability triggered (pre‑MIC validation in many code paths)
    → Attacker code execution on target's Wi‑Fi SoC
    → No host OS involvement required

PHASE 5: INSTALL
    → Write new entries to target's DBPP patch table
    → Redirect wlc_d11_raw_tx, wlc_security_check_mic, coex functions
    → Establish persistence mechanisms

PHASE 6: PERSISTENCE
    → Maintain access until reboot
    → Monitor for reinfection opportunities
    → Prepare for next propagation cycle

PHASE 7: REPEAT
    → Newly compromised device begins own recon cycle
    → Exponential spread through susceptible population
```

### Temporal Characteristics Supporting Worm Hypothesis
- **Brief activation windows**: 6.4‑second cycles (observed in event log) minimize detection risk.
- **Periodic behavior**: Allows coexistence with normal device operation.
- **Channel agility**: Frequency hopping avoids persistent spectral anomalies.
- **Minimal RF footprint**: Short bursts reduce probability of spectrum monitoring detection.

## 5. Impact Scenarios

### Individual Device Impact
- **Privacy violation**: Complete network traffic surveillance (as seen in foreign packet capture).
- **Credential theft**: Capture of passwords, session tokens, private keys (from HTTP/DNS traffic).
- **Device compromise**: Persistent foothold for further exploitation (via DBPP patch table modification).
- **Battery drain**: Unauthorized radio activity increases power consumption.

### Network‑Level Impact
- **Credential harvesting**: Mass collection of enterprise credentials (from cross‑subnet traffic capture).
- **Lateral movement facilitation**: Compromised devices as pivot points (via propagation mechanism).
- **Supply chain risk**: Infection of development/test devices (broad impact across iPhone/iPad/Mac lines).
- **IoT/OT bridging**: Potential jump to other wireless protocols (though not directly observed, the dual‑radio nature suggests capability).

### Organizational Impact
- **Data exfiltration**: Silent theft of sensitive information (via stealthy capture and potential exfiltration channels).
- **Authentication bypass**: Capture of MFA tokens, session cookies (from intercepted web traffic).
- **Intellectual property loss**: Theft of proprietary designs, code (from HTTPS traffic to internal services).
- **Reputation damage**: Loss of customer/trust confidence if exploited at scale.

## 6. Detection & Mitigation Strategies

### Detection Opportunities
1. **Wi‑Fi Firmware Monitoring**:
   - Alert on register value `0x3f80028` in event logs (promiscuous mode activation).
   - Monitor for unexpected promiscuous mode activation.

2. **Bluetooth HCI Monitoring**:
   - Alert on "unexpected scan core sleep state" messages (coexistence violations, as seen at offset 0x3D4623).
   - Track anomalous LE connection attempts (phantom connections to 00:00:00:00:00:00).

3. **Network‑Level Indicators**:
   - Unexpected cross‑subnet traffic in device logs (foreign subnet 172.17.177.0/24 while device on 172.20.14.0/24).
   - Anomalous mDNS/Bonjour query patterns.
   - AWDL traffic spikes from single devices.

4. **Host‑Based Indicators**:
   - Unexplained battery drain.
   - Performance anomalies during radio activity.
   - Unexpected wake events.

### Mitigation Priorities
**Short‑term (Operational)**:
- Network segmentation to limit cross‑subnet exposure.
- Enhanced wireless intrusion detection systems (WIDS).
- Device behavior monitoring for anomalous radio activity.
- Audit logs for coexistence violations.

**Medium‑term (Vendor)**:
- **Broadcom**: Implement hardware‑enforced privilege separation (MPU) to restrict firmware access to safety‑critical registers.
- **Broadcom**: Add cryptographic verification to DBPP mechanism (signature verification on patch code and integrity monitoring).
- **Apple**: Implement host‑side register verification (shadow registers or direct hardware status reads).
- **Both**: Improve coexistence message authentication (secure inter‑processor communication with integrity checks).

**Long‑term (Architectural)**:
- Redesign trust boundaries in integrated wireless SoCs (separate firmware execution environments with hardware isolation).
- Implement runtime firmware integrity monitoring (continuous verification of patch table and code).
- Develop cross‑vendor standards for coexistence security.
- Consider hardware root of trust for firmware validation (to prevent persistent firmware modification).

## 7. Assumptions & Limitations

### Assumptions
1. The observed artifacts represent genuine exploitation activity (not a false positive or test artifact).
2. The BCM4387C2 architecture is consistent across affected device generations (iPhone 12‑15 series, compatible iPads, select MacBooks).
3. The threat actor's goals include persistence and propagation (inferred from capability set).
4. Similar vulnerabilities may exist in other generations of BCM43xx SoCs (given architectural continuity).

### Limitations
1. Cannot determine the exact initial infection vector from the available artifacts (only post‑compromise state observed).
2. Unable to confirm payload specifics without access to the patch code in RAM (which resides outside the 2MB dump for some functions).
3. Propagation model is inferred from capabilities, not directly observed (no evidence of actual device‑to‑device transfer in the dump).
4. Effectiveness of mitigations depends on specific threat actor tradecraft and implementation details.

This threat model is grounded in the forensic evidence presented in the vulnerability report and serves to contextualize the risk and potential impact of the BroadScope vulnerability. All technical details regarding the observed capabilities are anchored to the specific byte offsets and artifacts described in `VULNERABILITY_REPORT.md`.
