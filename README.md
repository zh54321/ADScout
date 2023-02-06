# ADScout

Yet another small Powershell helper.

Main functions:
- Check preconditions (credentials, domain, dc reachable etc.) especially on a non domain joined host (aka pentest VM).
- Check AD modules available or load AD-DLL to memory (useful on Host without RSAT)
- Write everything manually specified during connection setup to a config to avoid to type it again and again.
- Quick spawn of another PS process with the runas same user and auto import module + config (just the users password needed if in runas mode).
- Easy rename of windows titles to find the right window on the taskbar
- Easy credential testing
- Quick single port check (much faster than test-netconnection)
- Can run as an in-memory function (New-Module -Name ADScout -ScriptBlock {Paste here} )

Planned:
- Auth test on users which are allowed to have an empty password
- Quick basic but useful info about the domain
- Various export functionalities (user export for pw spraying, user, computers, admins etc.)
- User lockout / bad pw monitor (useful during pw spraying)
