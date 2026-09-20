# Current Task — Bootstrap AAR Contracts

Status: bootstrap

## Objective

Establish the minimum public contract for AAR before implementing recovery workers.

## In scope

- public/private authority boundary;
- stable recovery primitives and invariants;
- initial repository layout;
- golden-workload and environment-spelunking role;
- thin integration contracts with Agent Dispatch and Model Artifact Foundry;
- falsifiable MVP/kill criteria.

## Out of scope for this increment

- downloading third-party APK corpora;
- broad analyzer implementation;
- committing large binaries;
- generic scheduler/router/database;
- automatic artifact promotion;
- vulnerability-scanning product scope;
- tool-specific canonical data models.

## Acceptance

A fresh contributor should be able to determine:
1. what AAR owns;
2. what Agent Dispatch owns;
3. what Model Artifact Foundry owns;
4. where private/restricted evidence belongs;
5. which invariants any implementation must preserve.
