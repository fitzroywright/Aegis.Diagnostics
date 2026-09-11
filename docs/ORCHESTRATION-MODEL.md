# Aegis.Diagnostics Orchestration Model

Aegis.Diagnostics is the centralized operator and orchestration application for engineering diagnostics. Reusable diagnostic contracts, execution policy, run storage abstractions, evidence models, and check infrastructure belong in Common.Diagnostics. Application-specific diagnostic checks remain in each monitored application.

## Responsibilities

Aegis.Diagnostics owns the cross-application concerns that do not belong in Common.Diagnostics:

- target/application registration and discovery;
- remote-safe diagnostic initiation;
- consolidated cross-application run history and audit visibility;
- operator workflows for escalation, review, and resolution;
- diagnostic playbook selection and presentation;
- notification fan-out to providers such as Slack, Teams, and email;
- environment and organization-aware target grouping where required;
- correlation of related diagnostic runs across independently deployed applications.

## Safety boundary

Aegis.Diagnostics may initiate diagnostics remotely, but diagnostic execution must remain non-destructive by default. Level 2 Repair and Level 1 Critical Intervention require an engineering reason and explicit authorization. A diagnostic run does not itself grant permission to execute destructive repair actions.

Any future repair or intervention action should be:

1. explicitly selected by an authenticated operator;
2. narrowly scoped to a registered safe action or playbook;
3. separately authorized where required;
4. fully auditable;
5. followed by verification and captured evidence.

## Target registration

Targets are registered through Aegis.Diagnostics configuration and expose the uniform Common.Diagnostics wire protocol. Each target identifies its application name/type, base URL, health endpoint, diagnostic run endpoints, and machine-authentication requirements.

Registration belongs to the Aegis.Diagnostics application layer. It must not require monitored applications to reference Aegis.Diagnostics or any retired Aegis.Engineering package.

## Audit and history

The operator console should present local and remote diagnostic runs as immutable evidence. Resolution metadata records closure without rewriting historical failed or intervention-required results as Passed.

Cross-application history should preserve at minimum:

- application and environment;
- run ID and level;
- requester identity and reason;
- timestamps;
- overall status;
- individual check results and evidence;
- resolution metadata;
- target identity and correlation metadata when available.

## Notifications

Notification providers are an orchestration concern. Aegis.Diagnostics may notify operators when runs fail, require intervention, are resolved, or meet other configured escalation rules. Provider-specific notification logic should remain behind application-level interfaces and must not be embedded in Common.Diagnostics contracts.

## Ownership boundary

- **Common.Diagnostics**: reusable contracts, lifecycle definitions, diagnostic engine, policy, evidence, retention abstractions, reusable checks.
- **Monitored applications**: application-specific checks and local runtime knowledge.
- **Aegis.Diagnostics**: target registration, remote orchestration, operator console, cross-application history, playbooks, correlation, notifications, and resolution workflows.

The retired Aegis.Engineering repository is not part of the runtime architecture.
