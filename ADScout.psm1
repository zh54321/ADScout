<#
    .Synopsis
    AD Pentest Helper
    .Description
    A module to help with common task in an AD pentest.
    .LINK
    https://github.com/zh54321/ADScout
#>

function ADS-title {
    <#
        .Synopsis
        Adjust the PS WIndow Title
        .DESCRIPTION
        Rename the window title to find in better in the taskbar.
        If the console runs in another user context (run as) this information will be preserved.
        .Parameter newtitle
        Title string
        .Example
        ADS-title Recon
        .LINK
        https://github.com/zh54321/ADScout
    #>
    Param($newtitle)
    $windowtitle=$host.UI.RawUI.WindowTitle
    $values = @('wird als','running as')
    $regexValues = [string]::Join('|',$values) 
    if($windowtitle -match $regexValues ){
        $windowtitle = $windowtitle -split ("\(|\)")
        $host.ui.RawUI.WindowTitle = "ADS: $newtitle ($($windowtitle[1]))"
    } else {
        $host.ui.RawUI.WindowTitle = "ADS: $newtitle"
    }

}

################ INIT
write-host ' ____________________________________________________'
write-host '|[] PowerShell                                 _ [] x|'
write-host '|""""""""""""""""""""""""""""""""""""""""""""""""""|"|'
write-host '|PS:C\> write-host "ADScout"                       | |'
write-host '| _  _  __                                         | |'
write-host '||_|| \(_  _  _    _|_                             | |'
write-host '|| ||_/__)(_ (_)|_| |_                             | |'
write-host '|__________________________________________________|_|'
write-host "[*] Doing setup stuff"
write-host "[*] Changeing title (use 'ADS-title %String%' to change it)"
ADS-title PowerShell
if (!($MyInvocation.MyCommand)) {
    write-host "[*] Fileless mode detected"
    write-host "[*] Defining default values (fileless)"
    $ADScout = [ordered]@{
        DN                  = $null
        OutFolder           = '$pwd.path'
        Connectioncheck     = $null
        Domain              = $null
        Dcip                = $null
        runas               = $null
        DnsOK               = $null
        UseDLL              = $null
        Fileless            = $true
    }
    New-Variable -Name ADScout -Value $ADScout -Scope Global -Force
} else {
    write-host "[*] Defining default values"
    $ADScout = [ordered]@{
        OutFolder           = (Split-Path -Parent $MyInvocation.MyCommand.Path | Join-Path -ChildPath ads_out)
        EnvConfig           = (Split-Path -Parent $MyInvocation.MyCommand.Path | Join-Path -ChildPath envconfig.xml)
        Module              = ($MyInvocation.MyCommand.Path)
        DN                  = $null
        Connectioncheck     = $null
        Domain              = $null
        Dcip                = $null
        runas               = $null
        DnsOK               = $null
        UseDLL              = $null
        Fileless            = $false
    }
    New-Variable -Name ADScout -Value $ADScout -Scope Global -Force
    #Check if config exist and attempt to load it. Load default values if failing
    if(test-path -Path ($ADScout.EnvConfig) -PathType Leaf) {
        write-host "[+] Config file detected. Try to load.."
        try {
            $ADScout = Import-Clixml ($ADScout.EnvConfig)
            write-host "[+] Config imported:"
            Write-Host ($ADScout | Format-table -Force | Out-String)
            if($ADSScout.UseDLL) {
                write-host "[*] According to config the Microsoft.ActiveDirectory.Management.dll was used."
                ADS-preconditioncheck
            }
            write-host "[i] If this is wrong, type to relead with default: ADS-wrongconfig"
        }
        catch {
            ############################### only defined if loading failed but whatr is if no config exist?
            write-host "[-] Config does not work"$PSItem
            write-host "[*] Renaming failed config to 'envconfig.xml.failed'"
            Rename-Item -Path $ADScout.EnvConfig -NewName "envconfig.xml.failed"
        }
    }
    If(!(test-path -PathType container $ADScout.OutFolder)) {
        New-Item -ItemType Directory -Path $ADScout.OutFolder
    }
}


function ADS-commands {
    <#
        .Synopsis
        Show the exported commands of the module
        .Example
        ADS-commands
        .LINK
        https://github.com/zh54321/ADScout
    #>
    Get-Module ADScout | % { $_.ExportedCommands.Values} | % {get-help $_} | ft name, synopsis
}



#Write config in case new values etc.
function ADS-writeconfig {
    if (!($ADScout.fileless)) {
        write-host "[*] Saving config:"$ADScout.EnvConfig
        $ADScout | Export-Clixml $ADScout.EnvConfig
    }
}

function ADS-wrongconfig {
    write-host "[*] Renaming config and reload module"
    If((test-path -PathType Leaf $ADScout.EnvConfig)) {
        Rename-Item -Path $ADScout.EnvConfig -NewName "envconfig.xml.wrong"
    }
    import-module $ADScout.Module -force -DisableNameChecking
}

#Function to reload with new config
function ADS-title {
    <#
        .Synopsis
        Adjust the PS WIndow Title
        .DESCRIPTION
        Rename the window title to find in better in the taskbar.
        If the console runs in another user context (run as) this information will be preserved.
        .Parameter newtitle
        Title string
        .Example
        ADS-title Snaffler
        .LINK
        https://github.com/zh54321/ADScout
    #>
    Param($newtitle)
    $windowtitle=$host.UI.RawUI.WindowTitle
    $values = @('wird als','running as')
    $regexValues = [string]::Join('|',$values) 
    if($windowtitle -match $regexValues ){
        $windowtitle = $windowtitle -split ("\(|\)")
        $host.ui.RawUI.WindowTitle = "ADS: $newtitle ($($windowtitle[1]))"
    } else {
        $host.ui.RawUI.WindowTitle = "ADS: $newtitle"
    }

}

#Function to spawn a new shell with the same use
function ADS-cpshell {
    <#
        .SYNOPSIS
        Start a new shell (same run as user) and import the module + config
        
        .DESCRIPTION
        The function checks if the shell runs as another user (based on windows title) and starts a new shell.
        In the new shell the ADScout module is imported and the config is loaded (if present).
        No parameters...

        .EXAMPLE
        ADS-cpshell

        .LINK
        https://github.com/zh54321/ADScout
    #>
    if(!$ADS.fileless) {
        ADS-detectrunas
        if($ADScout.runas) {
            write-host "[+] Staring new shell as"$ADScout.runas
            runas /netonly /user:$($ADScout.runas) "powershell.exe -exec bypass -NoExit -Command import-module $($ADScout.Module) -force -DisableNameChecking"
        } else {
            write-host "[*] Not in a different usercontext, starting normal shell"
            Start-Process pwsh -exec bypass -NoExit -Command import-module $($ADScout.Module) -force -DisableNameChecking
            start-process powershell "import-module $($ADScout.Module)"
            ################# BUG!!!!!!!!!!!!!!!!!!!
        }
    } else {
        write-host "[!] Currently not available in fileless mode"
    }

}

function ADS-detectrunas {
    $windowtitle=$host.UI.RawUI.WindowTitle
    $values = @('wird als','running as')
    $regexValues = [string]::Join('|',$values) 
    if($windowtitle -match $regexValues ){
        $windowtitle = $windowtitle -split ("\(|\)")
        $windowtitle = $windowtitle[1] -split (" ")
        $useranddomain = $windowtitle[2]
        $ADScout.runas = $useranddomain 
        write-host "[+] Script Running as" $ADScout.runas
    } else {
        $ADScout.runas = $false
    }
}

function ADS-out {
    #[cmdletbinding()]
    <#
        .Synopsis
        Write to to Screen and logfile, export to file
        .DESCRIPTION
        Used to keep track of what has been done
        .Parameter action
        Actions: 
        Write only to log no output: logonly
        Write to log and output (default):logandout
        Export to file: export
        Export to file CSV: export
        .Parameter function
        Used as prefix of the logfile
        .Parameter custom
        Custom string
        .Parameter object
        Stuff to log/export
        .Example
        Get-process | ADS-writelogandoutput
        .Example
        ADS-writelogandoutput "logandprint" "CustomFunction" $Result
    #>
    param
    (
        [ValidateSet("logandprint", "logonlye", "export", "exportcsv")]    
        [String[]]
        $action = "logandprint",
        [String[]]
        $function = "custom",
        [String[]]
        $custom,
        [Parameter(Mandatory,ValueFromPipeline)]
        [object]
        $object
    )
    $all = @($input)
    $date = Get-Date -Format "yyyyMMdd"
    $date_ext = Get-Date -Format "yyyyMMdd_hhmmss"

    #If custom is defined add proper seperator
    if ($custom) {
        $customstring= $custom + "_"
    }
    
    # If filelessmode outputfolder is current path
    if ($ADScout.Fileless) {
        $ADScout.OutFolder = $pwd.path
    }
    
    switch ($action){
        "logandprint" {
            $Logfile = Join-Path $ADScout.OutFolder ("\log_"+$function+"_"+$customstring+$date+".txt")
            Tee-Object -InputObject $all -FilePath $Logfile -Append
        }
        "logonly" {
            $Logfile = Join-Path $ADScout.OutFolder ("\log_"+$function+"_"+$customstring+$date+".txt")
            $all | Out-File -FilePath $Logfile -Append
        }
        "export" {
            $Logfile = Join-Path $ADScout.OutFolder ("\export_"+$function+"_"+$customstring+$date_ext+".txt")
            $all | Out-File -FilePath $Logfile -Append
        }
        "exportcsv" {
            $Logfile = Join-Path $ADScout.OutFolder ("\export_"+$function+"_"+$customstring+$date_ext+".csv")
            $all | Export-Csv -Path $Logfile -Append -NoTypeInformation
        }
    }
}

#Function to check if credentials are valid
function ADS-testcred {
    <#
        .SYNOPSIS
        Test the credential of a user
        
        .DESCRIPTION
        Test the credential of a user. The user will be defined interactivly.
        No parameters...

        .EXAMPLE
        ADS-testcred
        .LINK
        https://github.com/zh54321/ADScout
    #>
    $cred = Get-Credential -Credential "$($ADScout.domain)\"
    if ($ADScout.DnsOK) { ## DEBUG: TEST on System with DNS
        write-host "[+] DNS OK using System.DirectoryServices.DirectoryEntry method"
        write-host "[i] Enter username (no domain needed) and password."
        $username = $cred.username
        $password = $cred.GetNetworkCredential().password
    
        # Get current domain using logged-on user's credentials
        $CurrentDomain = "LDAP://" + $ADScout.DN
        write-host "[*] Testing credentials for: $username"
        $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$UserName,$Password)
    
        if ($domain.name -eq $null) {
            write-host "[-] Auth failed."
        } else {
            write-host "[+] Successfully authenticated with domain $($domain.name)"
        }

    } else {
        write-host "[-] DNS NOK (re-run ADS-Connectioncheck again if you think otherwise)"
        write-host "[*] Using get-addomain for test."

        #Ensure var does not exit
        if($credentialtest) {
            remove-variable credentialtest -Force
        }
        # Test auth
        try {
            $credentialtest = get-addomain -Credential $cred -Identity $ADScout.domain -Server $ADScout.dcip -ErrorAction Stop          
        }         
        #Handle auth issues
        catch [System.Security.Authentication.AuthenticationException] {
            Write-Host "[-] Credentials not valid: $PSItem" -ForegroundColor DarkRed
        }
        catch {
            Write-Host "[!] Something else went wrong: $PSItem" -ForegroundColor DarkRed
        }

        if (($credentialtest | Measure-Object).count -gt 0) { 
            write-host "[+] Successfully authenticated with: $($cred.UserName)"
        }
    }

}

function ADS-getDomainInfo
{
    ADS-checkpreconditions
    $functionname = $MyInvocation.MyCommand
    $timestamp = Get-Date -Format "yyyyMMdd hh:mm:ss"

    "============================= GET Domain Info @$timestamp ============================" | ads-out -function $functionname
    "---------Domain Info---------"  | ads-out -function $functionname
    Get-ADDomain -Server $ADScout.dcip | select-object Forest,DomainMode,UsersContainer,ComputersContainer,InfrastructureMaster,ParentDomain,ChildDomains | ads-out -function $functionname
    "---------Objects---------" | ads-out -function $functionname
    "AD Users:"+(Get-ADUser -Filter * -Server $ADScout.dcip).Count+" (Enabled:"+(Get-AdUser -Server $ADScout.dcip -filter 'Enabled -eq $false').count+")"| ads-out -function $functionname
    "AD Groups:"+(Get-ADGroup -Filter * -Server $ADScout.dcip).Count | ads-out -function $functionname
    "AD Computers:"+(Get-ADComputer -Filter * -Server $ADScout.dcip).Count+" (Enabled:"+(Get-ADComputer -Server $ADScout.dcip -filter 'Enabled -eq $false').count+")"| ads-out -function $functionname

    "---------DC Info---------"| ads-out -function $functionname
    Get-ADDomainController -Server $ADScout.dcip | select-object Hostname,IPv4Address, IsReadOnly, IsGlobalCatalog,OperatingSystem,OperationMasterRoles,ComputerObjectDN | format-table | ads-out -function $functionname

    "---------Admin Groups (contain string admin)---------" | ads-out -function $functionname
    Get-ADGroup -Filter 'Name -like "*admin*"' -Properties * -Server $ADScout.dcip | select-object SAMAccountName, @{l='Members';e={($_.Members.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}},@{n='MemberOf';e={($_.MemberOf.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}},DistinguishedName,Description |Out-GridView  | ads-out -function $functionname

    Write-Host "---------Users in the Admin Groups (recursive search)---------" | ads-out -function $functionname

    #Get-ADGroup -Filter 'Name -like "*admin*"' -Properties * -Server $ADScout.dcip | get-adgroupmember -Recursive -Server $ADScout.dcip | Get-ADUser -Properties SamAccountName,Enabled,PasswordLastSet,DoesNotRequirePreAuth,Description,memberof -Server $ADScout.dcip | select-object SamAccountName,Enabled,PasswordLastSet,DoesNotRequirePreAuth,Description,@{l='Member Of';e={($_.memberof.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}} | sort-object -Property SamAccountName -Unique | format-table

    "---------Misc---------" | ads-out -function $functionname
    Get-ADObject -Identity ((Get-ADDomain -Server $ADScout.dcip).distinguishedname) -Properties ms-DS-MachineAccountQuota -Server $ADScout.dcip| select-object ms-DS-MachineAccountQuota | ads-out -function $functionname

}
function fulluserexport
{
    ADS-checkpreconditions
    $functionname = $MyInvocation.MyCommand
    $timestamp = Get-Date -Format "yyyyMMdd hh:mm:ss"

    Write-Host "====================================================="
    Write-Host "=============== Export Full user list================"
    Write-Host "====================================================="
    Write-Host 
    $table = Get-ADUser -Properties * -Filter * -Server $domain | Select-Object SamAccountName,CN,Enabled,LockedOut,badPwdCount,PasswordLastSet,PasswordExpired,CanonicalName,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,PasswordNotRequired,@{n='servicePrincipalName';e={$_.servicePrincipalName.Value -join ';'}},TrustedToAuthForDelegation,@{n='PrincipalsAllowedToDelegateToAccount';e={$_.PrincipalsAllowedToDelegateToAccount.Value -join ';'}},Description | Export-Csv -Encoding "utf8" -NoTypeInformation -path users.csv
    pause
    Show-CustomMenu
}

function ADS-expwspraying
{
    <#
        .Synopsis
        Export a list of user for PW-spraying
        .DESCRIPTION
        Export a lsit of users (samAccountname) for PW spraying.
        Only select accounts which are: enabled, not locked, badpwcount=0.
        Supports an interactivemode to select the desired user in a gridview and an export by last pw changedate.
        .Parameter byyear
        Export users by year they changed the password.
        .Parameter interactive
        Starts an interactive gridview to select the users to export.
        .Example
        ADS-expwspraying
        .Example
        ADS-expwspraying -interactive
    #>
    Param (

        [ValidateSet("normal", "byyear")]    
        [String[]]
        $mode = "normal",
        [Parameter(HelpMessage='Will start an interactive Gridview to choose the users')]
        [switch]
        $interactive
    )

    ADS-checkpreconditions
    $functionname = $MyInvocation.MyCommand
    $timestamp = Get-Date -Format "yyyyMMdd hh:mm:ss"

    "[*] Start -------Export Users for PW Spray-------" | ads-out -function $functionname

    if ($interactive){    
        Get-ADUser -Properties SamAccountName,LockedOut,badPwdCount,PasswordExpired,LastLogonDate,logonCount,whenCreated,whenChanged,ServicePrincipalNames, CanonicalName, Department, Description, Memberof, PasswordLastSet -Filter {Enabled -eq "true"} -Server $ADScout.Dcip | where-object {$_.LockedOut -eq 0 -and $_.badPwdCount -eq 0} | select-object SamAccountName, logonCount,LastLogonDate, PasswordLastSet, whenChanged, whenCreated,ServicePrincipalNames, CanonicalName, Department, Description, Memberof | Out-GridView -Title "ADScout: Choose users for Export" -PassThru | Select-Object SamAccountName -ExpandProperty SamAccountName | ads-out -function $functionname -action export
        "[+] Exporting the accounts to $($ADScout.OutFolder)" | ads-out -function $functionname
    } elseif ($mode -eq "byyear") {
        #Get the las pwd change by year, if never changed the pwd get the creation date
        $table = Get-ADUser -Properties SamAccountName,LockedOut,badPwdCount,PasswordExpired,PasswordLastSet,whenCreated -Filter {Enabled -eq "true"} -Server $ADScout.Dcip | where-object {$_.LockedOut -eq 0 -and $_.badPwdCount -eq 0} | select-object samaccountname, @{n='PasswordLastset';e={if ($_.PasswordLastSet.year -gt 1970){$_.PasswordLastSet.year} else{ $_.whencreated.year} }}
        "[+] Password age structure:" | ads-out -function $functionname
        $table | Group-Object -Property PasswordLastSet -NoElement | Sort-Object -Property PasswordLastSet -Descending  | ads-out -function $functionname

        $uniqueyears = $table.PasswordLastset | Select-Object -Unique

        foreach ($year in $uniqueyears) {
            $table | Where-Object PasswordLastset -EQ $year | Select-Object SamAccountName -ExpandProperty SamAccountName | ads-out -function $functionname -action export -custom users$year
        }
        #badpwdcount is not replicated https://learn.microsoft.com/de-de/windows/win32/adschema/a-badpwdcount?redirectedfrom=M
    } else {
        "[*] Searching users which are: Enabled, not locked, no badpwdcount" | ads-out -function $functionname
        $table = Get-ADUser -Properties SamAccountName,LockedOut,badPwdCount,PasswordExpired,PasswordLastSet,whenCreated -Filter {Enabled -eq "true"} -Server $ADScout.Dcip | where-object {$_.LockedOut -eq 0 -and $_.badPwdCount -eq 0} | select-object samaccountname, @{n='PasswordLastset';e={if ($_.PasswordLastSet.year -gt 1970){$_.PasswordLastSet.year} else{ $_.whencreated.year} }}
        
        "[+] Password age structure:" | ads-out -function $functionname
        $table | Group-Object -Property PasswordLastSet -NoElement | Sort-Object -Property PasswordLastSet -Descending  | ads-out -function $functionname

        "[+] Found $($table.count) Users. Exporting to $($ADScout.OutFolder)" | ads-out -function $functionname 
        $table | Select-Object SamAccountName -ExpandProperty SamAccountName | ads-out -function $functionname -action export
    }
}

function ADS-explorerUsers
{
    ADS-checkpreconditions
    $functionname = $MyInvocation.MyCommand
    $timestamp = Get-Date -Format "yyyyMMdd hh:mm:ss"

    Write-Host "[*] Start -------Exploring AD users-------"
    Get-ADUser -Properties SamAccountName,LockedOut,badPwdCount,PasswordExpired,Enabled -Server $ADScout.Dcip | Out-GridView -PassThru | get-aduser -Properties * | ADS-out -function $functionname

}

function checkuser
{

    Write-Host "===================================================="
    Write-Host "================ Check User Details ================"
    Write-Host "===================================================="
    $user = Read-Host "Username"
    Get-ADUser -Identity $user -Properties * -Server $domain
    write-host "test"
    pause
    Show-CustomMenu
}


function ADS-portcheck {
    <#
        .Synopsis
        Simple single port check
        .DESCRIPTION
        A simple and fast (compared to test-netconnection) port check (TCP Full connection).
        Give back true or false depending if the connection has been established.
        .Parameter address
        IP address of the target
        .Parameter port
        Port to check
        .Parameter timeout
        How long (ms) to wait for reply (default is set to 1000ms).
        .Example
        ADS-portcheck 10.10.10.10 389
        .Example
        ADS-portcheck 10.10.10.10 389 4000
    #>
    Param (
        $address,
        [ValidateRange(1,65535)]
        [int] 
        $port,
        [ValidateRange(0,999999)]
        [int] 
        $timeout=1000
    )

    $socket=New-Object System.Net.Sockets.TcpClient
    try {
        $result=$socket.BeginConnect($address, $port, $NULL, $NULL)
        if (!$result.AsyncWaitHandle.WaitOne($timeout, $False)) {
            $open = $false
        } else {
            $open = $true
        }               
    }
    finally {
        $socket.Close()
    }
    return($open)
}

function ADS-checkpreconditions {
    <#
        .Synopsis
        Checking if preconditions are met (internal only)
    #>
    if (!$ADScout.Connectioncheck) {
        ADS-connectionchecks
    }
}


function ADS-preconditioncheck
{
    # Check if AD commands from an ActiveDirctory modules are available
    if ((Get-Command -Module *ActiveDirectory*).count -gt 100) {
        Write-host "[+] AD Module seems to be installed"
        $ADSScout.UseDLL = $false
        return $true
    } else {
        Write-host "[-] AD PS Module not available (install RSAT!)"      
        # Check if dll exist if yes, import.
        Write-host "[*] Check if Microsoft.ActiveDirectory.Management.dll in module folder exist"
        if (Test-Path -Path $ADSmodulebasepath\ADdll.psm1) {
            Write-host "[+] DLL exist. Importing..."
            import-module $ADSmodulebasepath\ADdll.psm1 -WarningAction silentlyContinue
            $ADSScout.UseDLL = $true
            Write-host "[!] Not all functionalities tested. Use at own risk..."
            return $true
        } else {
            Write-host "[!] No AD PS module or Microsoft.ActiveDirectory.Management.dll found." -ForegroundColor DarkRed
            return $false
        }
    }
}


function ADS-connectionchecks
{
    <#
        .Synopsis
        Perfoming connection checks to the domain.
        .DESCRIPTION
        Functions which is perfoming connections check to the domain.
        If information can't be colelcted automatically (domain joined host) asks for user input.
        It ensures:
            - Domain is defined (either if runned on a domain joined host or by user input)
            - DC ip is defined (either by dns lookup or by user input)
            - DC is reachable on port 9389 (AD Webservice)
            - User has the rights to query (either use the local credentials or use runas)
            - Domain information can be tretived
        If successful it will set the global var ADSconnectioncheck to $true and write config (to skip the checks next time)
    #>

    # Check for AD module or AD dll
    if (!(ADS-preconditioncheck)) {
        break
    }

    # Check for AD module or AD dll
    if ($ADScout.Connectioncheck) {
        $ADScout.Connectioncheck = $false
    }

     # Check if Domain query is possible
    write-host "[*] Perfoming AD connectivity check"
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().name
        Write-host "[+] Host is domain joined: $domain"
    }
    catch {
        Write-host "[-] Current host is not member of a Domain"
        [bool] $domjoined = 0;
        #Detect runas
        ADS-detectrunas
    }
   
    while(!$ADScout.Connectioncheck){
        

        if (!$domain) {
            $domain = Read-Host "[i] Specify Domain"
        }       

        #DNS CHECKS if not resolveable ask for IP
        if(!$dcip) {
            Write-Host "[*] Trying lookup (DNS): $domain"
            try {
                #!!!!!!!!!!!!!!!!!!!!! Check if PDC should be autoselect to get accurate badpassword count!!!!!!!!!!!!
                #if valid domain used and can be resolved take the first dc ip.
                $dcip = Resolve-DnsName -Type A -Name $domain -ErrorAction Stop | select-object -ExpandProperty IPAddress -First 1
                Write-host "[+] Domainname can be resolved: $dcip"
                $ADScout.DnsOK = $true
            } catch {
                $ADScout.DnsOK = $false
                Write-Host "[-] Can't resolve (DNS): $domain"
                $dcip = Read-Host "[i] Specify DC IP (idealy the PDC)"
            }
        }

        #Verify reachability of the Domain and if the right domainname provided
        Write-Host "[*] Trying to get domain info from:$domain using DC IP: $dcip"
        try {
            $domaintest = get-addomain -Identity $domain -Server $dcip -ErrorAction Stop          
        } 
        
        #Handle auth issues
        catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
            Write-Host "[!] Connection issue: $PSItem" -ForegroundColor DarkRed
            Write-Host "[*] Test connection: TCP 9389 on $dcip"
            if (ADS-portcheck $dcip 9389) {
                Write-Host "[+] Connection OK - TCP 9389 on $dcip"
                Write-Host "[!] No idea whats wrong :-(" -ForegroundColor DarkRed
                throw
            } else {
                Write-Host "[!] Can't connect to ADWeb Service: $PSItem" -ForegroundColor DarkRed
                Remove-Variable dcip -Force
            }
        }

        #Handle auth issues
        catch [System.Security.Authentication.AuthenticationException] {
            Write-Host "[!] Access issue: $PSItem" -ForegroundColor DarkRed
            Write-Host "[!] Important: If not domain joined, start the powershell: runas /netonly /user:%domain%\%user% powershell" -ForegroundColor DarkRed
            exit
        }

        #Handle wrong domain name issues
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] 
        {
            Write-Host "[!] Connection to DC sucessfull but Domain not found: $PSItem" -ForegroundColor DarkRed
            Remove-Variable domain -Force
        }

        #Handle unknow issues
        catch {
            Write-Host "[!] Unknow error: $PSItem" -ForegroundColor DarkRed
            
            #DEBUG
            $PSItem | Select-Object -Property *
            throw
        }

        # Check if connection successfully if not loop
        if (($domaintest | Measure-Object).count -gt 0) {   
            $ADScout.Connectioncheck = $true   
            $ADScout.Domain = $domain
            $ADScout.Dcip = $dcip
            $ADScout.DN = $domaintest.DistinguishedName
            Write-Host "[+] Connection check successfull with: $domain"
            #Write config to disk
            ADS-writeconfig
        }
    }
}

## Maybe alternativ if no RSAT ([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties}
Export-ModuleMember -Function ADS-commands,ADS-getDomainInfo,ADS-connectionchecks,ADS-cpshell,ADS-testcred,ADS-title,ADS-expwspraying,ADS-portcheck, ADS-out, ADS-explorerUsers
#Export-ModuleMember -function *


#Get-Command -module ADScout | write-host
