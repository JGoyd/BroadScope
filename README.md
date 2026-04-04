# BroadScope: BCM4387 Autonomous Promiscuous Capture 

This repository contains forensic analysis of the **BroadScope** vulnerability in the Broadcom BCM4387 Wi‑Fi/Bluetooth SoC, including evidence of active exploitation captured in a RAM dump.

## Contents

- `README.md` – This overview file  
- `VULNERABILITY_REPORT.md` – Detailed technical vulnerability report with byte‑offset anchored evidence  
- `THREAT_MODEL.md` – Analysis of threat model, attack vectors, and propagation capabilities  

## Overview

Analysis reveals:  

1. **Architectural Vulnerability** – Unverified ROM patch table (DBPP) allows runtime modification of 86 critical functions without integrity verification.  
2. **Observed Exploitation** – Forensic artifacts show the chip entering promiscuous mode (register value `0x3f80028`) and retaining traffic from unrelated devices in its DMA buffers, indicating unauthorized cross‑subnet capture.  
3. **Propagation Potential** – Capabilities such as raw 802.11 frame injection, AWDL handler modification, and autonomous BLE connection attempts suggest the vulnerability could support wireless propagation between devices.  
4. **Broad Impact** – The flaw resides in the BCM4387C2 chip architecture itself, affecting all devices using this SoC: iPhone 12‑15 series, compatible iPad models (iPad Air 2020+ and others), and select MacBook models (M1 Pro, M2 Air, etc.).  

All technical claims are anchored to specific byte offsets in the provided artifacts for verification.

## Artifacts Analyzed

- `SoC_RAM.bin` (2,068,480 bytes) – BCM4387C2 Wi‑Fi firmware RAM dump  
- `bluetoothd-hci-2025-06-28_13-25-26.pklg` (4,997,407 bytes) – Bluetooth HCI packet log  


This analysis represents independent research. 

