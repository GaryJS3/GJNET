# Project guidance

- Prefer C#. Keep app behavior and integration adapters in C#.
- Avoid Python and YAML. Docker Compose configuration is JSON.
- Keep private addresses, inventory, credentials, and runtime data out of the public repository.
- Preserve fail-closed guest visibility and explicit proxy trust. Use read-only upstream APIs.
- Run `dotnet build -c Release` and `dotnet run --project tests/GJNET.Checks` for behavioral changes.
- Distinguish local verification, container deployment, and real network integration validation in reports.
