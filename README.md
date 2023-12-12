# ADScout (Work in progress)

Yet another small Powershell AD Pentest helper.
Main focuse are quality of life improvements.

# Features

Main functions so far:
- Check preconditions (credentials, domain, dc reachable etc.) especially on a non domain joined host (aka pentest VM).
- Write everything manually specified during connection setup to a config to avoid to type it again and again the paramters of each command (domain name, DC IP, DN etc.). The config is loaded again on module import.
- Check AD modules available or load AD-DLL to memory (useful on Host without RSAT)
- Quick spawn of another PS process with the same runas-user and auto import module + config (just the users password needed if in runas mode).
- Easy rename of windows titles to find the right window on the taskbar
- Found credentials? Easy credential validity testing.
- Quick single port check (much faster than test-netconnection)
- Can whole module run as an in-memory function (New-Module -Name ADScout -ScriptBlock {Paste here} )
- Logging function which log the results of the different functions to not miss anything for documentation
- Export users for password spraying (Interactive mode, normale mode, grouped by last pw changedate)

Planned:
- Auth test on users which are allowed to have an empty password
- Quick basic but useful info about the domain
- Various export functionalities (user, computers, admins etc.)
- User lockout / bad pw monitor (useful during pw spraying)

## Show available commands

Show the available commands

Example:
```powershell
ADS-commands
```

## Set a windows-Title

Rename the window title to find in better in the taskbar.
If the console runs in another user context (run as) this information will be preserved.

Example:
```powershell
ADS-title Snaffler
```

## Open a new PS Window

The function checks if the shell runs as another user (based on windows title) and starts a new shell.
In the new shell the ADScout module is imported and the config is loaded (if present).
No parameters...

Example:
```powershell
ADS-cpshell
```

## Test credentials

Foun credentials and want an easy way to test it?
Test the credential of a user. The user will be defined interactivly.
No parameters...

Example:
```powershell
ADS-testcred
```


# Functions
## Export Users for Password spraying

Used to export usernames (samaccountname) for password spraying.

There are 3 different modes available (all only select users which are: enabled, not locked and badpwcount is 0.).
- Default: Export all users for password spraying
- Interactive: Open a outgridview to interactivly search/filter the user which should be exported
- ByYear: A user which set his password in 2021 will mostlikly not have the password Summer2023!. Therefore the script export the users according the year when the pw has been set the last time. If it never has been set the account creation date is taken instead.


Example:
```powershell
Normal:
ADS-expwspraying
ADS-expwspraying -mode normal

Interactive:
ADS-expwspraying -interactive

ByYear:
ADS-expwspraying -mode byyear
```

## Get basic domain information (needs to be improved)

Get some domain information like:
- Domain information
- Domain Controllers
- Count of USers / Groups / Computers
- Some interesting groups

Example:
```powershell
ADS-getDomainInfo
```

## Single port scan

A simple and fast (compared to test-netconnection) port check (TCP Full connection).
Give back true or false depending if the connection has been established.

Takes 2 parameters:
- Port: Port to check
- Timeout: How long (ms) to wait for reply (default is set to 1000ms).

Example:
```powershell
ADS-portcheck 10.10.10.10 389

ADS-portcheck 10.10.10.10 389 4000
```


