# Phase 3: Governing an AI Agent as a Non-Human Identity

Design intent. No code yet. This document states how the engine extends to treat an AI agent as a first-class non-human identity, governed by the same lifecycle the engine already applies to roles, users, and keys.

## Why an agent is an NHI

An AI agent authenticates, holds permissions, calls tools and AWS APIs, and acts with autonomy. That makes it a non-human identity in every sense the engine already cares about: it needs an accountable owner, a credible credential model, a least-privilege boundary, and an offboarding path. AWS has reached the same conclusion. Amazon Bedrock AgentCore Identity (in preview) manages agents as workload identities with agent-specific attributes, each with its own ARN and a centralized directory that acts as the unit of governance. Governing those identities is the frontier of NHI governance, and the engine's existing model maps onto it directly.

## What the engine would govern

The same detectors, pointed at an agent's identity and its execution role, with two agent-specific additions:

| Concern | Maps to | What is checked |
|---|---|---|
| Accountable owner | NHI1:2025 Improper Offboarding, NIST AC-2 | The agent identity carries an owner; retired agents and their credentials are deprovisioned. |
| Credential model | NHI4:2025 Insecure Authentication, NHI7:2025 Long-Lived Secrets, NIST IA-5 | The agent authenticates with short-lived, vaulted credentials rather than static API keys. AgentCore Identity separates credential storage from access so the agent never holds long-term secrets directly; the engine scores anything that bypasses that as degraded. |
| Execution-role privilege | NHI5:2025 Overprivileged NHI, NIST AC-6 | The agent's IAM execution role and its tool/action scope grant only what the agent needs, no wildcards. |
| Inbound trust | NHI6:2025 Insecure Cloud Deployment Configurations, NIST IA-9 | Who can invoke the agent is scoped to intended callers, not left open. |
| Accountability and audit | NHI10:2025 Human Use of NHI | Agent actions are distinguishable from human ones and every credential use is logged. |

## Agent-specific risk the classic detectors do not yet cover

Two failure modes are unique to agents and worth their own detectors:

- Delegation and impersonation. An agent acting on behalf of a user can over-reach if the delegated scope is broader than the task. The engine should flag agent identities whose on-behalf-of scope exceeds the caller's own permissions.
- Confused-deputy via prompt injection. An agent can be induced to misuse its legitimate permissions. The mitigation is not detection of the prompt but tight least privilege and scoped, short-lived tokens, so the blast radius of a manipulated agent stays small. This is why the execution-role and credential-model checks above matter more for agents than for ordinary workloads.

## Design

A new collector, conceptually `BedrockAgentCoreCollector`, reads the agent identity directory and each agent's execution role over read-only APIs and emits the same `NHIRecord` the rest of the engine consumes. Records flow through the existing detectors and reporter, producing the same control-mapped JSON evidence, so an agent shows up in a scan beside roles and users, scored on the same axes. Credential-model classification extends to recognize vaulted, short-lived agent credentials as the target state and static API keys as the worst.

## Status

Design intent, not implemented. Bedrock AgentCore is in preview and subject to change, so the collector targets the concepts (agent identity as a workload identity, an execution role, an inbound authorizer, a credential vault) rather than a frozen API surface. The point of this phase is to show that the engine's governance model, owner, credential posture, least privilege, and offboarding, applies unchanged to the fastest-growing class of non-human identity.
