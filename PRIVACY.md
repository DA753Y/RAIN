# RAIN privacy policy

Effective 15 July 2026

RAIN is a browser extension for sending indicators you select to security research and hunting tools. It has no user accounts, advertising, analytics, telemetry, or RAIN-operated backend service.

## What RAIN handles

RAIN reads text that you select or paste when you use one of its hunt actions. It uses that text in the browser to identify the indicator type, refang common defanging, and build the destination URL or Microsoft Defender query you requested.

Your settings and custom KQL templates are stored locally using Chromium extension storage. Short-lived interface and injection state may be stored in session storage. RAIN does not transmit this information to its developer.

## When data leaves the browser

An indicator is sent to a third-party service only when you deliberately choose that service or use a grouped search that includes it. The selected service receives the indicator as part of its URL or request, and its own privacy policy applies. Public reputation services may not be appropriate for internal hostnames, employee accounts, or sensitive incident indicators.

When you choose Microsoft Defender Advanced Hunting, RAIN opens `https://security.microsoft.com` and fills the editor with a query for you to review. RAIN does not run the query.

## Data sharing and retention

RAIN does not sell personal information, share information for advertising, or retain a copy of your indicators on a developer-controlled system. Removing the extension removes its locally stored extension data according to Chromium's normal extension-removal behaviour.

## Contact

Questions can be raised through [GitHub Issues](https://github.com/DA753Y/RAIN/issues). Do not include sensitive indicators or incident data in a public issue.
