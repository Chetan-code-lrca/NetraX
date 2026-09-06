# NetraX

AI-based detection of cyber threats in strictly unidirectional IP traffic.

NetraX is being developed for Smart India Hackathon problem statement SIH26145.

## Core Idea

NetraX performs passive, read-only threat detection using only the traffic visible inside a monitoring enclave.

The system does not send probes, queries, handshakes, or mitigation commands back into the production network.

## Key Innovation

### One-Way Threat Separability Engine

The Separability Engine evaluates whether a threat can be reliably distinguished using the evidence available from a strictly one-way observation point.

It helps identify:

- DETECTABLE
- WEAKLY-SEPARABLE
- NOT-SEPARABLE

and avoids overconfident conclusions when critical reverse-side evidence is unavailable.

## Current Detection

- Port Scan
- DDoS
- C2 / Botnet Beaconing
- DNS-based threats

## Architecture

```text
One-way traffic
      ↓
Feature extraction
      ↓
Threat-specific detection
      ↓
One-Way Threat Separability Engine
      ↓
Evidence-aware alert
      ↓
Dashboard / monitoring
Project Status

Prototype under active development.
