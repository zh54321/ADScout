<#
 .Synopsis
  AD Pentest Helper
 .Description
  A module to help with common task in an AD pentest.
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
cd ($MyInvocation.MyCommand.Path | Split-Path -Parent)
write-host "[*] Defining default values"
$ADScout = [ordered]@{
    Logfolder           = ($MyInvocation.MyCommand.Path | Split-Path -Parent | Join-Path -ChildPath logs)
    Lootfolder          = ($MyInvocation.MyCommand.Path | Split-Path -Parent | Join-Path -ChildPath loot)
    EnvConfig           = ($MyInvocation.MyCommand.Path | Split-Path -Parent | Join-Path -ChildPath envconfig.xml)
    Module              = ($MyInvocation.MyCommand.Path)
    DN                  = $null
    Connectioncheck     = $null
    Domain              = $null
    Dcip                = $null
    runas               = $null
    DnsOK               = $null
    UseDLL              = $null
}

#Check if config exist and attempt to load it. Load default values if failing
if(test-path -Path ($MyInvocation.MyCommand.Path | Split-Path -Parent | Join-Path -ChildPath envconfig.xml) -PathType Leaf) {
    write-host "[+] Config file detected. Try to load.."
    try {
        $ADScout = Import-Clixml ($MyInvocation.MyCommand.Path | Split-Path -Parent | Join-Path -ChildPath envconfig.xml)
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

New-Variable -Name ADScout -Value $ADScout -Scope Global -Force

If(!(test-path -PathType container $ADScout.Logfolder)) {
    New-Item -ItemType Directory -Path $ADScout.Logfolder
}
If(!(test-path -PathType container $ADScout.Lootfolder)) {
    New-Item -ItemType Directory -Path $ADScout.Lootfolder
}


#Write config in case new values etc.
function ADS-writeconfig {
    write-host "[*] Saving config:"$ADScout.EnvConfig
    $ADScout | Export-Clixml $ADScout.EnvConfig
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


function ADS-writelogandoutput {
    #Todo
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
        write-host "[*] Testing credentials for:"+$username
        $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$UserName,$Password)
    
        if ($domain.name -eq $null) {
            write-host "[-] Auth failed."
        } else {
            write-host "[+] Successfully authenticated with domain $domain.name"
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
            write-host "[+] Successfully authenticated with:"$cred.UserName
        }
    }

}

function ADS-interactive
{
    if (!$connectioncheck){ADS-connectionchecks}
    Clear-Host
    Write-Host "================ Options ================"
    Write-Host 
    Write-Host "---Generic Info---"
    Write-Host "1: Domain Info (incl. DCs, Admin groups)"
    Write-Host "2: Export full user list"
    Write-Host 
    Write-Host "--- Weakness Stuff ---"
    Write-Host "3: Exploit suggestions"
    Write-Host "4: Show vuln users (1 table)"
    Write-Host
    Write-Host "--- Lookups ---"
    Write-Host "5: Check attributes of a single user"
    Write-Host "6: GPO Search & Dump (Name)"
    Write-Host "7: GPO Search & Dump (Content based)"
    Write-Host
    Write-Host "--- PW Spraying---"
    Write-Host "9: Export userlist for PW Spraying"
    Write-Host "0: Monitore User Lockouts"
    Write-Host
    Write-Host "Q: Quit"
    Write-Host 
    Write-host
    # Choose
    $choice = Read-Host "Choose"

    # Select option
    switch ($choice){
  
        '1' {getDomainInfo}
        '2' {fulluserexport}
        '3' {vulnuserexport}
        '4' {showvulnuser}
        '5' {checkuser}
        '6' {gposearchname}
        '7' {gposearchcontent}
        '9' {pwsprayinguserexport}
        '0' {monitorelockouts}
            'q' {exit}
        }
}


function ADS-getDomainInfo
{
    ADS-check
    #Clear-Host
    Write-Host "======================================================"
    Write-Host "=================== GET Domain Info =================="
    Write-Host "======================================================"
    Write-Host
    Write-Host "---Domain Info---"
    Get-ADDomain -Server $ADScout.dcip | select-object Forest,DomainMode,UsersContainer,ComputersContainer,InfrastructureMaster,ParentDomain,ChildDomains
    Write-Host "---Objects---"
    Write-Host "AD Users:"(Get-ADUser -Filter * -Server $ADScout.dcip).Count"(Enabled:"(Get-AdUser -Server $ADScout.dcip -filter 'Enabled -eq $false').count")"
    Write-Host "AD Groups:"(Get-ADGroup -Filter * -Server $ADScout.dcip).Count
    Write-Host "AD Computers:"(Get-ADComputer -Filter * -Server $ADScout.dcip).Count"(Enabled:"(Get-ADComputer -Server $ADScout.dcip -filter 'Enabled -eq $false').count")"
    Write-Host
    Write-Host "---DC Info---"
    Get-ADDomainController -Server $ADScout.dcip | select-object Hostname,IPv4Address, IsReadOnly, IsGlobalCatalog,OperatingSystem,OperationMasterRoles,ComputerObjectDN | format-table
    Write-Host
    Write-Host "---Admin Groups (contain string admin)---"
    Get-ADGroup -Filter 'Name -like "*admin*"' -Properties * -Server $ADScout.dcip | select-object SAMAccountName, @{l='Members';e={($_.Members.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}},@{n='MemberOf';e={($_.MemberOf.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}},DistinguishedName,Description |format-table
    Write-Host
    Write-Host "---Users in the Admin Groups (recursive search)---"
    Write-Host
    Get-ADGroup -Filter 'Name -like "*admin*"' -Properties * -Server $ADScout.dcip | get-adgroupmember -Recursive -Server $ADScout.dcip | Get-ADUser -Properties SamAccountName,Enabled,PasswordLastSet,DoesNotRequirePreAuth,Description,memberof -Server $ADScout.dcipp | select-object SamAccountName,Enabled,PasswordLastSet,DoesNotRequirePreAuth,Description,@{l='Member Of';e={($_.memberof.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}} | sort-object -Property SamAccountName -Unique | format-table
    Write-Host
    Write-Host "---Misc---"
    Get-ADObject -Identity ((Get-ADDomain -Server $ADScout.dcip).distinguishedname) -Properties ms-DS-MachineAccountQuota -Server $ADScout.dcip| select-object ms-DS-MachineAccountQuota
    Write-Host
}
function fulluserexport
{
    Clear-Host
    Write-Host "====================================================="
    Write-Host "=============== Export Full user list================"
    Write-Host "====================================================="
    Write-Host 
    $table = Get-ADUser -Properties * -Filter * -Server $domain | Select-Object SamAccountName,CN,Enabled,LockedOut,badPwdCount,PasswordLastSet,PasswordExpired,CanonicalName,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,PasswordNotRequired,@{n='servicePrincipalName';e={$_.servicePrincipalName.Value -join ';'}},TrustedToAuthForDelegation,@{n='PrincipalsAllowedToDelegateToAccount';e={$_.PrincipalsAllowedToDelegateToAccount.Value -join ';'}},Description | Export-Csv -Encoding "utf8" -NoTypeInformation -path users.csv
    pause
    Show-CustomMenu
}

function pwsprayinguserexport
{
    Clear-Host
    Write-Host "====================================================="
    Write-Host "============= User Export for PW Spraying============"
    Write-Host "====================================================="
    Write-Host 
    Write-Host "Searching for Accounts which are: Enabled, not locked, 0 badpwCount, PW is not expired"
    Write-Host
    $table = Get-ADUser -Properties SamAccountName,LockedOut,badPwdCount,PasswordExpired -Filter {Enabled -eq "true"} -Server $domain | where-object {$_.LockedOut -eq 0 -and $_.badPwdCount -eq 0-and $_.PasswordExpired -eq 0} | Select-Object SamAccountName -ExpandProperty SamAccountName
    Write-Host "Found"$table.count "Users. Usernames exportet to users_pw_spraying.txt"

    $domain = Get-ADDomain -Server $domain | select-object PDCEmulator,Forest
    Write-Host 
    Write-Host "Perform PW spraying with:"
    Write-Host "./kerbrute_linux_amd64 passwordspray -d"$domain.Forest"--dc"$domain.PDCEmulator"users_pw_spraying.txt 'Sommer2020!'"
    $table | Out-File -Encoding utf8 -FilePath users_pw_spraying.txt
    Write-Host 
    Write-Host 
    Write-Host "================ Options ================"
    
    $monlockouts = Read-Host "Monitore Lockouts? (y/n)"
    # Select option
    switch ($monlockouts){
         'y' {monitorelockouts}
         'n' {Show-CustomMenu}
     }
     Show-CustomMenu
}

function vulnuserexport
{
    Clear-Host
    Write-Host "====================================================="
    Write-Host "================ Exploit suggestions ================"
    Write-Host "====================================================="
    Write-Host 
    $table = Get-ADUser -Properties * -Filter * -Server $domain | Select-Object SamAccountName,CN,Enabled,LockedOut,badPwdCount,CanonicalName,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,PasswordNotRequired,@{n='servicePrincipalName';e={$_.servicePrincipalName.Value -join ';'}},TrustedForDelegation,TrustedToAuthForDelegation,@{n='PrincipalsAllowedToDelegateToAccount';e={$_.PrincipalsAllowedToDelegateToAccount.Value -join ';'}},@{n='msDS-AllowedToDelegateTo';e={$_."msDS-AllowedToDelegateTo".Value -join ';'}},Description

    $ReversiblePasswordEncryption = $table | Where-Object {$_.AllowReversiblePasswordEncryption -eq 1} | select-object SamAccountName,Enabled,AllowReversiblePasswordEncryption,CanonicalName,Description
    $ASREPRoastable = $table | Where-Object {$_.DoesNotRequirePreAuth -eq 1} | select-object SamAccountName,Enabled,DoesNotRequirePreAuth,CanonicalName,Description
    $Kerboroastable = $table | Where-Object {$_.servicePrincipalName -ne ''} | select-object SamAccountName,Enabled,servicePrincipalName,CanonicalName,Description
    $NoPWRequired = $table | Where-Object {$_.PasswordNotRequired -eq 1 -and $_.Enabled -eq 1} | select-object SamAccountName,Enabled,PasswordNotRequired,CanonicalName,Description
    $Unconstraineddelegation = $table | Where-Object {$_.TrustedForDelegation -eq 1} | select-object SamAccountName,Enabled,TrustedForDelegation,CanonicalName,Description
    $Constraineddelegation = $table | Where-Object {$_.TrustedToAuthForDelegation -ne ''} | select-object SamAccountName,Enabled,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo,CanonicalName,Description
    
    Write-Host "================ Overview ================ "
    Write-Host 
    if (($ReversiblePasswordEncryption | Measure-Object).count -gt 0) {write-host "Reversible PW encryption:" ($ReversiblePasswordEncryption | Measure-Object).count; $showrevpwenc = 1} else {write-host "Reversible PW encryption:0"}
    if (($ASREPRoastable | Measure-Object).count -gt 0) {write-host "ASREP roastable:" ($ASREPRoastable | Measure-Object).count; $showasproastable = 1} else {write-host "ASREP roastable: 0"}
    if (($Kerboroastable | Measure-Object).count -gt 0) {write-host "Kerboroastable:" ($Kerboroastable | Measure-Object).count; $showKerboroastable = 1} else {write-host "Kerboroastable: 0"}    
    if (($NoPWRequired | Measure-Object).count -gt 0) {write-host "NO PW required:" ($NoPWRequired | Measure-Object).count; $showNoPWRequired = 1} else {write-host "NO PW required: 0"}
    if (($Unconstraineddelegation | Measure-Object).count -gt 0) {write-host "Unconstrained delegation:" ($Unconstraineddelegation | Measure-Object).count; $showUnconstraineddelegation = 1} else {write-host "Unconstrained delegation: 0"}
    if (($Constraineddelegation | Measure-Object).count -gt 0) {write-host "Constrained delegation:" ($Constraineddelegation | Measure-Object).count; $showConstraineddelegation = 1} else {write-host "Constrained delegation: 0"}

    Write-Host 
    Write-Host 
    Write-Host "================ Details ================ "
    Write-Host 

   
    if ($showrevpwenc -eq 1) {
        write-host "ReversiblePasswordEncryption"
        write-host "-------------------------------------------------------------------------------------------------------------------------------------"
        write-host "Caused by: Accounts which have the 'Store password using reverisble encryption.."
        write-host "Attack: Need Domain admin or DC sync rights to retrive the cleartext PW!"
        write-host "Exploitation:"
        write-host "Use mimikatz: lsadump::dcsync /domain:fec.local /user:userrevpassword"
        write-host  
        write-host  "PS: IMO the PW has to be set AFTER the flag was activated otherwhise the pw isn't stored."
        write-host  
        $ReversiblePasswordEncryption | format-table
        $ReversiblePasswordEncryption | Export-Csv -Encoding "utf8" -NoTypeInformation -path reversiblepw_enc.csv
    } else {

    }    
    
    if ($showasproastable -eq 1) {
        write-host "ASREP roastable"
        write-host "-------------------------------------------------------------------------------------------------------------------------------------"
        write-host
        write-host "Caused by: Accounts which have the 'Do not require Kerberos preauthentication' flag set."
        write-host "Attack: send a fake AS-REQ, to receive the users Hash to crack it offline."
        write-host "Exploitation:"
        write-host "1. WINDOWS: Collect Hashes: Rubeus_v4.8.exe asreproast /format:hashcat /outfile:hashes.asreproast"
        write-host "1. LINUX: Create usernames.txt with the account names. Collect the Hashes (Impacket): python3 ./GetNPUsers.py dc1.fec.local/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast"
        write-host "2. Crack it with Hashcat: hashcat --attack-mode 0 --hash-type 18200 --optimized-kernel-enable hashes.asreproast /srv/wordlists/ALL-COMBINED.txt --rules-file /srv/rules/nsa_500.txt"
        write-host
        write-host "* Esspecially check non-service accounts, because they are more likely to have a weaker password!"
        write-host
        write-host "Affected accounts:"
        $ASREPRoastable | format-table
        $ASREPRoastable | Export-Csv -Encoding "utf8" -NoTypeInformation -path ASREPRoastable.csv
    } else {

    }

    if ($showKerboroastable -eq 1) {
        write-host "Kerboroasting"
        write-host "-------------------------------------------------------------------------------------------------------------------------------------"
        write-host
        write-host "Caused by: Accounts with SPN"
        write-host "Attack: Get the NTHash of a Service Account"
        write-host "Exploitation:"
        write-host "1. WINDOWS: Collect Hashes: Rubeus_v4.8.exe asreproast kerberoast /outfile:kerberoasting_hashes.txt"
        write-host "1. LINUX: Collect Hashes (Impacket): ./GetUserSPNs.py -request domain/username[:password]"
        write-host "2. Crack it with Hashcat: `hashcat --attack-mode 0 --hash-type 13100 --optimized-kernel-enable kerberoasting_hashes.txt --session=85xxx-kerberoast-quick /srv/wordlists/uncompressed/crackstation-human-only.txt --rules-file /srv/rules/nsa_500.txt"
        write-host
        write-host "Affected accounts:"
        $Kerboroastable | format-table
        $Kerboroastable | Export-Csv -Encoding "utf8" -NoTypeInformation -path kerboroastable.csv
    } else {

    }

    if ($showNoPWRequired -eq 1) {
        write-host "NO PW required"
        write-host "-------------------------------------------------------------------------------------------------------------------------------------"
        write-host
        write-host "Caused by: AD Account misconfiguration Attribut: userAccountControl"
        write-host "Attack: Try to login with an empty password."
        write-host "Exploitation:"
        write-host "1. LINUX: Performing kerbbrute: ./kerbrute_linux_amd64 passwordspray -d  contoso.com --dc XXX.contoso.com users.txt ''"
        write-host
        write-host "* Warning: Be carefull to not lock out the account!"
        write-host
        write-host "Affected accounts:"
        $NoPWRequired | format-table
        $NoPWRequired | Export-Csv -Encoding "utf8" -NoTypeInformation -path pwnotrequired.csv
    } else {

    }

    if ($showUnconstraineddelegation -eq 1) {
        write-host "Unconstrained delegation"
        write-host "-------------------------------------------------------------------------------------------------------------------------------------" 
        $Unconstraineddelegation | format-table
        $Unconstraineddelegation | Export-Csv -Encoding "utf8" -NoTypeInformation -path unconstraind_delegation.csv
    } else {

    }

    if ($showConstraineddelegation -eq 1) {
        write-host "Constrained delegation"
        write-host "-------------------------------------------------------------------------------------------------------------------------------------" 
        $Constraineddelegation | format-table
        $Constraineddelegation | Export-Csv -Encoding "utf8" -NoTypeInformation -path constrained_delegation.csv
    } else {

    }
    pause
    Show-CustomMenu
}

function showvulnuser
{
    Clear-Host
    Write-Host "================ Show Vuln User ================"
    $table = Get-ADUser -Properties * -Filter * -Server $domain | Select-Object SamAccountName,CN,Enabled,LockedOut,badPwdCount,CanonicalName,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,PasswordNotRequired,@{n='servicePrincipalName';e={$_.servicePrincipalName.Value -join ';'}},TrustedToAuthForDelegation,@{n='PrincipalsAllowedToDelegateToAccount';e={$_.PrincipalsAllowedToDelegateToAccount.Value -join ';'}},Description
    $table | Where-Object {$_.Enabled -eq 1 -and ($_.AllowReversiblePasswordEncryption -eq 1 -or $_.DoesNotRequirePreAuth -eq 1 -or $_.PasswordNotRequired -eq 1 -or $_.servicePrincipalName -ne '' -or $_.TrustedToAuthForDelegation -ne '' -or $_.PrincipalsAllowedToDelegateToAccount -ne '')} | format-table
    pause
    Show-CustomMenu
}

function checkuser
{
    Clear-Host
    Write-Host "===================================================="
    Write-Host "================ Check User Details ================"
    Write-Host "===================================================="
    $user = Read-Host "Username"
    Get-ADUser -Identity $user -Properties * -Server $domain
    write-host "test"
    pause
    Show-CustomMenu 
}

function monitorelockouts
{

    $lockedout = Get-ADUser -properties samaccountname,LockedOut, badPwdCount, LastBadPasswordAttempt,LastLogonDate -filter * -Server $domain | where-object {$_.LockedOut -eq 1} | select-object samaccountname,LockedOut, badPwdCount, LastBadPasswordAttempt,LastLogonDate | format-table

    while($true) {
        Clear-Host
        Write-Host "====================================================="
        Write-Host "================  Monitore Lockouts  ================"
        Write-Host "====================================================="
        Write-Host 
        Write-Host "Check performed:" (get-date).ToString('T')
        if ($lockedout) { $lockedout }else {write-host "No locked account found."}
        Start-Sleep -Milliseconds 5000
        $lockedout = Get-ADUser -properties samaccountname,LockedOut, badPwdCount, LastBadPasswordAttempt,LastLogonDate -filter * -Server $domain | where-object {$_.LockedOut -eq 1} | select-object samaccountname,LockedOut, badPwdCount, LastBadPasswordAttempt,LastLogonDate | format-table
    }
    
}

function gposearchname
{
    Clear-Host
    Write-Host "====================================================="
    Write-Host "================== GPO Search Name =================="
    Write-Host "====================================================="
    Write-Host
    Write-Host "Search for a GPO (name). Leave empty to display and dump all."
    Write-Host
    $searchstring = Read-Host "Search string"
    write-host 
    $hitGposInDomain = Get-GPO -All -Domain $forest | where-object {$_.DisplayName -like "*$searchstring*"}
    $listgpo = ''
    $resultsgpo = New-Object System.Collections.ArrayList
    $resultsgporights = New-Object System.Collections.ArrayList

    foreach ($gpo in $hitGposInDomain) {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $forest


        write-host "- Match in: $($gpo.DisplayName)" -foregroundcolor "Green"
        [xml]$xmlElm = $report
        $report | Out-File -FilePath ("GPO_" + $gpo.DisplayName + ".txt")
        Get-GPOReport -Guid $gpo.Id -ReportType html -Domain $forest | Out-File -FilePath ("GPO_" + $gpo.DisplayName + ".html")
        $listgpo = New-Object System.Object
        $listgpo | Add-Member -MemberType NoteProperty -Name "GPO Name" -Value $gpo.DisplayName     
        $listgpo | Add-Member -MemberType NoteProperty -Name "Enabled Computer" -Value $xmlElm.GPO.Computer.Enabled
        $listgpo | Add-Member -MemberType NoteProperty -Name "Enabled User" -Value $xmlElm.GPO.User.Enabled
        $listgpo | Add-Member -MemberType NoteProperty -Name "Link Path (OU)" -Value $xmlElm.GPO.LinksTo.SOMPath
        $listgpo | Add-Member -MemberType NoteProperty -Name "Enabled Link" -Value $xmlElm.GPO.LinksTo.Enabled
        $listgpo | Add-Member -MemberType NoteProperty -Name "GPO ID" -Value $gpo.Id
        $resultsgpo.Add($listgpo) | Out-Null

        
        foreach ($object in $xmlElm.GPO.SecurityDescriptor.Permissions.TrusteePermissions) {
            $listgporights = New-Object System.Object
            $listgporights | Add-Member -MemberType NoteProperty -Name "GPO Name" -Value $gpo.DisplayName 
            $listgporights | Add-Member -MemberType NoteProperty -Name "Group" -Value $object.Trustee.Name."#text"
            $listgporights | Add-Member -MemberType NoteProperty -Name "rights" -Value $object.Standard.GPOGroupedAccessEnum

            $resultsgporights.Add($listgporights) | Out-Null
        }
        
        $resultsgporights.Add($listgporights) | Out-Null
        

    }
    write-host 
    write-host "--------------------GPO's found --------------------"
    $resultsgpo | format-table
    write-host "*The content of the policy has been saved as file in the current path."
    write-host 
    write-host "--------------------GPO rights--------------------"
    $resultsgporights | format-table

    pause
    Show-CustomMenu
}

function gposearchcontent
{


    Clear-Host
    Write-Host "======================================================"
    Write-Host "================= GPO Search Content ================="
    Write-Host "======================================================"
    Write-Host
    Write-Host "Search for a specific string in all GPO's. Leave empty to display and dump all."
    Write-Host
    $searchstring = Read-Host "Search string"
    write-host 
    $allGposInDomain = Get-GPO -All -Domain $forest
    $listgpo = ''
    $resultsgpo = New-Object System.Collections.ArrayList
    $resultsgporights = New-Object System.Collections.ArrayList

    foreach ($gpo in $allGposInDomain) {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $forest

        if ($report -match $searchstring) {
            write-host "- Match in: $($gpo.DisplayName)" -foregroundcolor "Green"
            [xml]$xmlElm = $report
            $report | Out-File -FilePath ("GPO_" + $gpo.DisplayName + ".txt")
            Get-GPOReport -Guid $gpo.Id -ReportType html -Domain $forest | Out-File -FilePath ("GPO_" + $gpo.DisplayName + ".html")
            $listgpo = New-Object System.Object
            $listgpo | Add-Member -MemberType NoteProperty -Name "GPO Name" -Value $gpo.DisplayName     
            $listgpo | Add-Member -MemberType NoteProperty -Name "Enabled Computer" -Value $xmlElm.GPO.Computer.Enabled
            $listgpo | Add-Member -MemberType NoteProperty -Name "Enabled User" -Value $xmlElm.GPO.User.Enabled
            $listgpo | Add-Member -MemberType NoteProperty -Name "Link Path (OU)" -Value $xmlElm.GPO.LinksTo.SOMPath
            $listgpo | Add-Member -MemberType NoteProperty -Name "Enabled Link" -Value $xmlElm.GPO.LinksTo.Enabled
            $listgpo | Add-Member -MemberType NoteProperty -Name "GPO ID" -Value $gpo.Id
            $resultsgpo.Add($listgpo) | Out-Null

        
            foreach ($object in $xmlElm.GPO.SecurityDescriptor.Permissions.TrusteePermissions) {
                $listgporights = New-Object System.Object
                $listgporights | Add-Member -MemberType NoteProperty -Name "GPO Name" -Value $gpo.DisplayName 
                $listgporights | Add-Member -MemberType NoteProperty -Name "Group" -Value $object.Trustee.Name."#text"
                $listgporights | Add-Member -MemberType NoteProperty -Name "rights" -Value $object.Standard.GPOGroupedAccessEnum

                $resultsgporights.Add($listgporights) | Out-Null
            }
        
            $resultsgporights.Add($listgporights) | Out-Null
        

        } else {
         write-host "- No Match: $($gpo.DisplayName)"
        }

    }
    write-host 
    write-host "--------------------GPO which contain the string--------------------"
    $resultsgpo | format-table
    write-host "*The content of the policy has been saved as file in the current path."
    write-host 
    write-host "--------------------GPO rights--------------------"
    $resultsgporights | format-table

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
    Param($address, $port, $timeout=1000)

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

function ADS-check {
    if (!$ADSconnectioncheck) {
        ADS-connectionchecks
    }
}


function ADS-preconditioncheck
{
    # Check if AD commands from an ActiveDirctory modules are available
    if ((Get-Command -Module *ActiveDirectory*).count -gt 100) {
        Write-host "[+] AD Module seems to be installed"
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
        Write-host "[+] Host is domain joined:"$domain
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
            Write-Host "[*] Trying lookup (DNS):"$domain
            try {
                #if valid domain used and can be resolved take the first dc ip.
                $dcip = Resolve-DnsName -Type A -Name $domain -ErrorAction Stop | select-object -ExpandProperty IPAddress -First 1
                Write-host "[+] Domainname can be resolved:"$dcip
                $ADScout.DnsOK = $true
            } catch {
                Write-Host "[-] Can't resolve (DNS):"$domain
                $dcip = Read-Host "[i] Specify DC IP"
            }
        }

        #Verify reachability of the Domain and if the right domainname provided
        Write-Host "[*] Trying to get domain info from:"$domain" using DC IP: "$dcip
        try {
            $domaintest = get-addomain -Identity $domain -Server $dcip -ErrorAction Stop          
        } 
        
        #Handle auth issues
        catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
            Write-Host "[!] Connection issue: $PSItem" -ForegroundColor DarkRed
            Write-Host "[*] Test connection: TCP 9389 on"$dcip
            if (ADS-portcheck $dcip 9389) {
                Write-Host "[+] Connection OK - TCP 9389 on"$dcip
                Write-Host "[!] No idea whats wrong :-(" -ForegroundColor DarkRed
                throw
            } else {
                Write-Host "[!] Can't connect to ADWeb Service: "$PSItem -ForegroundColor DarkRed
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
            Write-Host "[+] Connection check successfull with:"$domain
            #Write config to disk
            ADS-writeconfig
        }
    }
}

## Maybe alternativ if no RSAT ([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties}
#Export-ModuleMember -Function ADS-interactive,ADS-getDomainInfo,ADS-portcheck,
Export-ModuleMember -function *


#Get-Command -module ADScout | write-host
