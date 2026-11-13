# Project scope

- Keep this a read-only Claude Code environment diagnostic tool.
- Standard library + system curl only. No account manager, model gateway, daemon, automatic repair, or telemetry.
- Never execute Claude, settings hooks, shell startup files or Node preload to inspect their configuration.
- Do not read cookies, keychains, private keys, session history, or device/account identifiers.
- Never send API keys, OAuth tokens, cookies, code or model requests. Proxy credentials go to the selected proxy via curl stdin only.
- Unknown observations stay unknown. Do not turn HTTP 403, available IPv6, timezone differences, or third-party labels into ban verdicts.
- Keep proxy failures from silently falling back to direct requests. Verify TLS and do not follow redirects.
- Resolve route/endpoint ambiguity conservatively. Clearly document differences from the actual Claude runtime.
- Tests must use temporary directories and loopback mock services, not production accounts or public probes.
- Run `python3 -m unittest discover -s tests -v` after changing behavior. Keep reports out of Git.
