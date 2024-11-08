<# 
.Appu : AD Health checker
.Created by : Binu Balan
.Purpose : To scan Active Directory for Misconfiguration
#>

$version = "1.1"
$Logo1 = "
                                              
    ___    ____     _____                                 
   /   |  / __ \   / ___/_________ ____  ____  ___  _____
  / /| | / / / /   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ___ |/ /_/ /   ___/ / /__/ /_/ / / / / / / /  __/ /    
/_/  |_/_____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                       

==============================================
Author  : Binu Balan
Version : $version
==============================================
"

$logo2 = "

                                                                                               
  _|_|    _|_|_|          _|_|_|                                                              
_|    _|  _|    _|      _|          _|_|_|    _|_|_|  _|_|_|    _|_|_|      _|_|    _|  _|_|  
_|_|_|_|  _|    _|        _|_|    _|        _|    _|  _|    _|  _|    _|  _|_|_|_|  _|_|      
_|    _|  _|    _|            _|  _|        _|    _|  _|    _|  _|    _|  _|        _|        
_|    _|  _|_|_|        _|_|_|      _|_|_|    _|_|_|  _|    _|  _|    _|    _|_|_|  _|        
                                                                   

==============================================
Author  : Binu Balan
Version : $version
==============================================                                                                                                                                                                                                    
"

$logo3 = "
       _        _  _  _  _                _  _  _  _                                                                                          
     _(_)_     (_)(_)(_)(_)             _(_)(_)(_)(_)_                                                                                       
   _(_) (_)_    (_)      (_)_          (_)          (_)   _  _  _    _  _  _       _  _  _  _    _  _  _  _     _  _  _  _    _       _  _     
 _(_)     (_)_  (_)        (_)         (_)_  _  _  _    _(_)(_)(_)  (_)(_)(_) _   (_)(_)(_)(_)_ (_)(_)(_)(_)_  (_)(_)(_)(_)_ (_)_  _ (_)(_)    
(_) _  _  _ (_) (_)        (_)           (_)(_)(_)(_)_ (_)           _  _  _ (_)  (_)        (_)(_)        (_)(_) _  _  _ (_) (_)(_)          
(_)(_)(_)(_)(_) (_)       _(_)          _           (_)(_)         _(_)(_)(_)(_)  (_)        (_)(_)        (_)(_)(_)(_)(_)(_) (_)             
(_)         (_) (_)_  _  (_)           (_)_  _  _  _(_)(_)_  _  _ (_)_  _  _ (_)_ (_)        (_)(_)        (_)(_)_  _  _  _   (_)             
(_)         (_)(_)(_)(_)(_)              (_)(_)(_)(_)    (_)(_)(_)  (_)(_)(_)  (_)(_)        (_)(_)        (_)  (_)(_)(_)(_)  (_)             
                                                                                                                                        
                                                                                                                                        
"

$host.ui.rawui.windowsize.width = 200

Import-Module ActiveDirectory | Out-Null
Import-Module GroupPolicy | Out-Null

function checkuserperm() {

    Write-Host " [+] Running the precheck :" -ForegroundColor White -NoNewline

    $modulechk = (Get-Module -ListAvailable -Name ActiveDirectory).Name
    $modulechk1 = (Get-Module -ListAvailable -Name GroupPolicy).Name
    if ($modulechk -eq "ActiveDirectory" -and $modulechk1 -eq "GroupPolicy") {
        $isModuleAvailable = $true
        Write-Host " [Module] " -ForegroundColor Green -NoNewline
    }
    else {
        Write-Host " [Module] " -ForegroundColor Red -NoNewline
    }

    $memship = (Get-ADUser $env:USERNAME -Properties memberof).memberof
    ForEach ($mem in $memship) {
        if ($mem -like "*Domain Admins*") {
            $isDomAdmin = $true
        }
    }

    if ($isDomAdmin -eq $true) {
        Write-Host " [Privilege] " -ForegroundColor Green -NoNewline
    }
    else {
        Write-Host " [Privilege] " -ForegroundColor Red -NoNewline
    }

    if ([bool]((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        $isPs = $true
        Write-Host " [RunAsAdmin] " -ForegroundColor Green
    }
    else {
        Write-Host " [RunAsAdmin] " -ForegroundColor Red
    }



    if ($isDomAdmin -eq $true -and $isPs -eq $true -and $isModuleAvailable -eq $true) {
        # Write-Host "[PASSED]" -ForegroundColor White
    }
    else {
        # Write-Host "[FAILED]" -ForegroundColor Yellow
        Write-Host " 
        
        You Must have following pre-requisite fullfilled for this script to run:

                1. Powershell Active Directory and GroupPolicy Module.
                2. Run PowerShell as Admin.
                3. User must be part of Domain Admins Group.
        
        "
        Exit
    }


}


Function asrep($guid) {
    Write-Host " [+] AS-REP Query" -ForegroundColor White
    Get-ADUser -LDAPFilter '(&(&(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))))' | Export-Csv -NoTypeInformation asrep_$guid.csv | Out-Null
}

Function Kerberosting($guid) {
    Write-Host " [+] Keberosting Query" -ForegroundColor White
    Get-ADUSer -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName | Export-Csv -NoTypeInformation kerberosting_$guid.csv | Out-Null
}

Function PasswordNeverExpires($guid) {
    Write-Host " [+] Password Never Expires Query" -ForegroundColor White
    get-aduser -filter * -properties Name, PasswordNeverExpires | where { $_.passwordNeverExpires -eq "true" } | Export-Csv -NoTypeInformation PasswordNeverExpires_$guid.csv | Out-Null
}

Function SysvolPerm($guid) {
    Write-Host " [+] AD Sysvol Permission Check" -ForegroundColor White
    # $env:USERDOMAIN
    # Add-Content -Value "---- Sysvol with unexpected permission will be displayed below ----" -Path Sysvolperm_$guid.txt
    $permList = (Get-Acl \\$env:USERDOMAIN\sysvol).Access
    ForEach ($perm in $permList) {
        $checkwho = $perm.IdentityReference
        if ($checkwho -like "*Authenticated Users*" -or $checkwho -like "*SYSTEM*" -or $checkwho -like "*Administrators*" -or $checkwho -like "*Server Operators*" -or $checkwho -like "*CREATOR OWNER*") {
            # Do Nothing
        }
        Else {
            # Add-Content -Value $perm.IdentityReference -Path Sysvolperm_$guid.txt
            $perm | Export-Csv -Append -NoTypeInformation -Path Sysvolperm_$guid.csv
        }

        if ($checkwho -like "*Authenticated Users*") {
            $checkperm = $perm.FileSystemRights
            # Write-Host $checkperm -ForegroundColor Yellow
            if ($checkperm -eq -1610612736 -or $checkperm -eq "ReadAndExecute, Synchronize") {
                # Write-Host "Looks Good"  
            }
            else {
                $idname = $perm.IdentityReference
                $idexcess = $checkperm
                #Add-Content -Value "Excess Permission : $idname | $idexcess" -Path Sysvolperm_$guid.txt
                $perm | Export-Csv -Append -NoTypeInformation -Path Sysvolperm_$guid.csv
            }
        }
    }
}

Function Netlogonperm($guid) {
    Write-Host " [+] AD Netlogon Permission Check" -ForegroundColor White
    # $env:USERDOMAIN
    # Add-Content -Value "---- Netlogon with unexpected permission will be displayed below ----" -Path Netlogonperm_$guid.txt
    $permList = (Get-Acl \\$env:USERDOMAIN\Netlogon).Access
    ForEach ($perm in $permList) {
        $checkwho = $perm.IdentityReference
        if ($checkwho -like "*Authenticated Users*" -or $checkwho -like "*SYSTEM*" -or $checkwho -like "*Administrators*" -or $checkwho -like "*Server Operators*" -or $checkwho -like "*CREATOR OWNER*") {
            # Do Nothing
        }
        Else {
            # Add-Content -Value $perm.IdentityReference -Path Netlogonperm_$guid.txt
            $perm | Export-Csv -NoTypeInformation -Append -Path Netlogonperm_$guid.csv
        }
    }
}

function unexpectedFileShareOnAD($guid) {
    Write-Host " [+] Unexpected File Share detection on AD" -ForegroundColor White
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)
    ForEach ($dc in $allDC) {
        # Write-Host $dc
        $getShare = Get-SmbShare -CimSession $dc
        foreach ($share in $getShare) {
            $sname = $share.name
            if ($sname -like "*ADMIN$*" -or $sname -like "*C$*" -or $sname -like "*IPC$*" -or $sname -like "*CertEnroll*" -or $sname -like "*NETLOGON*" -or $sname -like "*SYSVOL*" -or $sname -like "*D$*" -or $sname -like "*E$*" -or $sname -like "*F$*") {
                # Write-Host $dc "|" $share.name
            }
            else {
                # Write-Host "UnknownShare - "$dc "|" $share.name
                $ushares = $share.name
                # Add-Content -Value "$dc - $ushares" -Path unexpectedFileShareOnAD_$guid.txt
                $share | Export-Csv -NoTypeInformation -Append -Path unexpectedFileShareOnAD_$guid.csv
            }

        }
    }
}

function RootHiddendelegate($guid) {
    Write-Host " [+] Checking Delegate access for Domain Root" -ForegroundColor White
    $DCval = (Get-ADDomain).DistinguishedName
    $ListPerm = (Get-Acl -Path "AD:$DCval").Access
    ForEach ($perms in $ListPerm) {
        if ($perms.IdentityReference -notlike "*NT AUTHORITY*" -and $perms.IdentityReference -notlike "*BUILTIN\*" -and $perms.IdentityReference -notlike "*Cloneable Domain Controllers*" -and $perms.IdentityReference -notlike "*Domain Admins*" -and $perms.IdentityReference -notlike "*Domain Controllers*" -and $perms.IdentityReference -notlike "*Enterprise Admins*" -and $perms.IdentityReference -notlike "*Enterprise Key Admins*" -and $perms.IdentityReference -notlike "*Enterprise Read-only Domain Controllers*" -and $perms.IdentityReference -notlike "*Key Admins*") {
            # "$perms.IdentityReference </td><td> $perms.ActiveDirectoryRights </td><td> $perms.AccessControlType" >> RootHiddendelegate_$guid.html
            $perms | Export-Csv -Append -NoTypeInformation RootHiddendelegate_$guid.csv
        }
    }
    # $ListPerm | Export-Csv -NoTypeInformation -Path RootHiddendelegate_$guid.txt

}

function ServiceAcct($guid) {
    Write-Host " [+] Fetching AD Service Account" -ForegroundColor White  
    Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToDelegateToAccount, PrincipalsAllowedToRetrieveManagedPassword | select DistinguishedName, Enabled, Name, SamAccountName, @{name = "PrincipalsAllowedToDelegateToAccount"; expression = { $_.PrincipalsAllowedToDelegateToAccount -join "; " } }, @{name = "PrincipalsAllowedToRetrieveManagedPassword"; expression = { $_.PrincipalsAllowedToRetrieveManagedPassword -join "; " } } | Export-Csv -NoTypeInformation -Append ServiceAcct_$guid.csv
}

function SMBNull($guid) {
    Write-Host " [+] Anonymous AD enumeration check" -ForegroundColor White
    # Add-Content -Value "----- Below list of AD allows Anonymous Access to AD ---- " -path anonymousSharesSAM_$Guid.csv
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)

    ForEach ($dc in $allDC) {
            
        $ra = Invoke-Command -ScriptBlock { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name restrictanonymous).restrictanonymous } -ComputerName $dc  # 0
        $ras = Invoke-Command -ScriptBlock { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name restrictanonymoussam).restrictanonymoussam } -ComputerName $dc # 1
        $eia = Invoke-Command -ScriptBlock { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name everyoneincludesanonymous).everyoneincludesanonymous } -ComputerName $dc # 0
        $rns = Invoke-Command -ScriptBlock { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").restrictnullsessaccess } -ComputerName $dc # 1

        if ($ra -eq 0 -and $ras -eq 1 -and $eia -eq 0 -and $rns -eq 1) {
            # Add-Content -Value "----- Below list of AD allows Anonymous Access to AD ---- " -path anonymousSharesSAM_$Guid.txt
        }
        else {
            Add-Content -Value "$dc , restrictanonymous = $ra , restrictanonymoussam = $ras , everyoneincludesanonymous = $eia , restrictnullsessaccess = $rns " -path anonymousSharesSAM_$Guid.csv
        }

    }
 
}

function GetPatchStatus($guid) {
    Write-Host " [+] Getting last 3 Patch install details from server." -ForegroundColor White
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)
    foreach ($dc in $allDC) {
        Get-Hotfix -ComputerName $dc | Sort-Object -Property InstalledOn -Descending | Select-Object -First 3 | Export-Csv -Append -NoTypeInformation -Path GetPatchStatus_$guid.csv
    }
}

function DomainAdmins($guid) {
    Write-Host " [+] Getting Domain Admins User lists" -ForegroundColor White
    Get-ADGroupMember "Domain Admins" -Recursive | Export-Csv -Append -NoTypeInformation -Path DomainAdmins_$guid.csv
}

function LLMR_NetBIOS($guid) {
    Write-Host " [+] Checking LLMNR, NetBIOS, MDNS status" -ForegroundColor White
    # Add-Content -Value "----- Below list of AD allows Anonymous Access to AD ---- " -path anonymousSharesSAM_$Guid.csv
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)
    # Netbios

    ForEach ($dc in $allDC) {
            
        $nb = Invoke-Command -ScriptBlock { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces\tcpip_*' -Name NetBiosOptions).NetBiosOptions } -ComputerName $dc  # 0
        
        foreach ($nbv in $nb) {
            if ($nbv -ne 0) {
                Add-Content -Value " $dc , NetBIOSOverTCP is Enabled" -path LLMR_NetBIOS_$guid.csv
            }
        }

        $mdns = Invoke-Command -ScriptBlock { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS).EnableMDNS } -ComputerName $dc  # 0
       
        if ($mdns -ne 0 -or $error) {
            Add-Content -Value " $dc , MDNS is Enabled" -path LLMR_NetBIOS_$guid.csv
        }
        $error.Clear()

        $llmnr = Invoke-Command -ScriptBlock { (Get-ItemProperty -Path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast).EnableMulticast } -ComputerName $dc  # 0

        if ($llmnr -ne 0 -or $error) {
            Add-Content -Value " $dc , LLMNR is Enabled" -path LLMR_NetBIOS_$guid.csv
        }
        $error.Clear()

    }
    
}

function DefaultOUUGC ($guid) {
    Write-Host " [+] Checking user/group part of default CN=User Container" -ForegroundColor White
    $DomainDN = (Get-ADDomain).DistinguishedName
    $userc = (Get-ADUser -SearchBase "CN=Users,$DomainDN" -Filter *).count
    $groupc = (Get-ADGroup -SearchBase "CN=Users,$DomainDN" -Filter *).count
    $contactc = ((Get-ADObject -Filter 'objectclass -eq "contact"' -SearchBase "CN=Users,$DomainDN").name).count
    Add-Content -Value "User , Group , contact " -Path DefaultOUUGC_$guid.csv
    Add-Content -Value "$userc , $groupc , $contactc" -Path DefaultOUUGC_$guid.csv
}

function AntivirusStatus ($guid, $AVServiceName){
    Write-Host " [+] Checking antivirus installation..." -ForegroundColor White
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)
    $AvState = "<B>ERROR Or NOT Found</B>"
    # Netbios
    Add-Content -Value "DomainController , Antivirus Name , AntivirusInstalled" -Path AntivirusStatus_$guid.csv
    ForEach ($dc in $allDC) {
        # $AvName = Invoke-Command -ScriptBlock { (Get-CimInstance -Class Win32_Service -Filter "Name = '$AVServiceName'" -server $dc | Select-Object state).state } -ComputerName $dc  # 0
        $AvState = (Get-CimInstance -Class Win32_Service -Filter "Name = '$AVServiceName'" -server $dc | Select-Object state).state
        # (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ComputerName $dc | select displayname -ExpandProperty displayname) -join ","
        # write-host "AV Name - $AvNameVal |  $AvStatusVal | $AvName" -ForegroundColor Green
        Add-Content -Value "$DC , $AVServiceName , $AvState" -Path AntivirusStatus_$guid.csv
    }
}

function unconstraintDelegation ($guid){
    Write-Host " [+] Unconstraint Delegation for Users and Machines..." -ForegroundColor White
    Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo | Select Name, msDS-AllowedToDelegateTo | Export-Csv -NoTypeInformation -Path UnconstraintDelegation_Comp_$guid.csv
    Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo | Select Name, msDS-AllowedToDelegateTo | Export-Csv -NoTypeInformation -Path UnconstraintDelegation_User_$guid.csv

    Get-ADuser -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation,serviceprincipalname,description | select SamAccountName,UserPrincipalName,TrustedForDelegation | Export-Csv -NoTypeInformation -Path TrustedforDelegation_User_$guid.csv
    Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation,serviceprincipalname,description | select SamAccountName,UserPrincipalName,TrustedForDelegation | Export-Csv -NoTypeInformation -Path TrustedforDelegation_Comp_$guid.csv
}

function DCSyncAccess($guid){
    Write-Host " [+] Checking for DCSync Access..." -ForegroundColor White
    $DCval = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl -Path "AD:$DCval"
    
    $searchDCSyncAccess = $acl.Access | Where-Object{($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "bf967aba-0de6-11d0-a285-00aa003049e2" -or $_.ObjectType -eq "00000000-0000-0000-0000-000000000001" -or $_.ObjectType -eq "00000000-0000-0000-0000-000000000002" -or $_.ObjectType -eq "00000000-0000-0000-0000-000000000000") } | select IdentityReference,IsInherited

    foreach($eachids in $searchDCSyncAccess){
        if($eachids -like "*ENTERPRISE DOMAIN CONTROLLERS*" -or $eachids -like "*Administrators*" -or $eachids -like "*Enterprise Read-only Domain Controllers*" -or $eachids -like "*Domain Controllers*" -or $eachids -like "*NT AUTHORITY\SYSTEM*" -or $eachids -like "*APPU\Enterprise Admins*" -or $eachids -like "*APPU\Domain Admins*" -or $eachids -like "*BUILTIN\Pre-Windows*"){
            # Do Nothing
        } else {
            $idval = $eachids.IdentityReference
            $eachids | Export-Csv -Path DCSyncAccess_$guid.csv -Append -NoTypeInformation
        }
    }
    <#
    https://www.sentinelone.com/blog/active-directory-dcsync-attacks/
    #>
}

function dumpntds($guid){
    Write-Host " [+] Checking which users have access to Dump NTDS.dit..." -ForegroundColor White
    Get-ADGroupMember "Backup Operators" -Recursive | Export-Csv -Append -NoTypeInformation -Path dumpntds_$guid.csv
    Get-ADGroupMember "Server Operators" -Recursive | Export-Csv -Append -NoTypeInformation -Path dumpntds_$guid.csv
    Get-ADGroupMember "Administrators" -Recursive | Export-Csv -Append -NoTypeInformation -Path dumpntds_$guid.csv
}

function GPOChangeAccess ($guid) {
    Write-Host " [+] Checking who can modify GroupPolicy" -ForegroundColor White
    $allGPO = Get-GPO -All
    Add-Content -Value "GPOName , Trustee , Permission" -Path GPOChangeAccess_$guid.csv
    foreach($eachgpo in $allGPO){
        $gpoguid = $eachgpo.Id
        $gponame = $eachgpo.DisplayName
        $gpperms = Get-GPPermission -Guid $gpoguid -All | Where-Object { $_.Permission -eq "GpoEdit" -or $_.Permission -eq "GpoEditDeleteModifySecurity" }
        foreach($gpperm in $gpperms){
            $Trustee = $gpperm.Trustee.Name
            $TrusteeType = $gpperm.TrusteeType
            $Permission = $gpperm.Permission
            if($Trustee -like "*SYSTEM*" -or $Trustee -like "*Domain Admins*" -or $Trustee -like "*Enterprise Admins*"){
                # Do nothing
            } else {
                # Write-Host "$gponame , $Trustee , $TrusteeType , $Permission" 
                "$gponame , $Trustee , $Permission" | Out-File GPOChangeAccess_$guid.csv -Append
            }
            
        }
    }    
}

function checkAdminRename($guid) {
    Write-Host " [+] Checking ADMINISTRATOR default account is renamed" -ForegroundColor White
    $DomainSID = (Get-ADDomain).DomainSID.value
    $sidval = $DomainSID + "-500"
    $CheckName = Get-ADUser -Filter 'SID -eq $sidval'
    $adminName = $CheckName.Name
    if($adminName -eq "Administrator"){
        '"Account_Name","Status"' | Out-File checkAdminRename_$guid.csv -Append
        '"Administrator","NOT RENAMED"' | Out-File checkAdminRename_$guid.csv -Append
    } else {
        # Do Nothing
    }
}

function ADDCList($guid) {
    Write-Host " [+] Listing all Domain Controllers and OU" -ForegroundColor White
    Get-ADDomainController -Filter * | select name,computerobjectDN | Export-Csv -NoTypeInformation -Path ADDCList_$guid.csv
}

function checkPasswordPolicy($guid) {
    Write-Host " [+] Checking Default Password Policy" -ForegroundColor White
    Get-ADDefaultDomainPasswordPolicy | select ComplexityEnabled,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled | Export-Csv -NoTypeInformation -Path checkPasswordPolicy_$guid.csv
}

function checkFSMO($guid) {
    Write-Host " [+] Checking FSMO Roles [Domain Wide and Forest Wide]" -ForegroundColor White
    Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator  | Export-Csv -NoTypeInformation -Path checkFSMODomain_$guid.csv
    Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster  | Export-Csv -NoTypeInformation -Path checkFSMOForest_$guid.csv
}


$host.ui.RawUI.WindowTitle = "AD Scanner [Binu Balan]"
cls
$ErrorActionPreference = "SilentlyContinue"
$FormatEnumerationLimit = -1
$guid = New-Guid 
$logoR = $logo1, $logo2, $logo3
$DisplayLogo = Get-Random $logoR
Write-Host $DisplayLogo -ForegroundColor (Get-Random "Green","Yellow", "White")

checkuserperm
$AVServiceName = Read-host " [?] Enter the Antivirus Service Name "
checkAdminRename $guid
checkFSMO $guid
checkPasswordPolicy $guid
asrep $guid
Kerberosting $guid
PasswordNeverExpires $guid
SysvolPerm $guid
unexpectedFileShareOnAD $guid
Netlogonperm $guid
RootHiddendelegate $guid
SMBNull $guid
ServiceAcct $guid
GetPatchStatus $guid
DomainAdmins $guid
LLMR_NetBIOS $guid
DefaultOUUGC $guid
AntivirusStatus $guid $AVServiceName
unconstraintDelegation $guid
DCSyncAccess $guid
dumpntds $guid
GPOChangeAccess $guid
ADDCList $guid

# LDAPport $guid
# OUHiddenDelegate $guid

function Report($guid){
    Write-Host " [+] Lets write some HTML Report..." -ForegroundColor Yellow
    $Header = $Header = @"
    <style>
        h1 {
    
            font-family: Arial, Helvetica, sans-serif;
            color: #000099;
            font-size: 28px;
        } 
        h2 {
            font-family: Arial, Helvetica, sans-serif;
            color: #000099;
            font-size: 16px;
        }
        h3 {
            font-family: Arial, Helvetica, sans-serif;
            color: #000099;
            font-size: 12px;
        }
       table {
            font-size: 12px;
            border: 0px; 
            font-family: Arial, Helvetica, sans-serif;
        } 
        td {
            padding: 4px;
            margin: 0px;
            border: 0;
        }
        th {
            background: #395870;
            background: linear-gradient(#49708f, #293f50);
            color: #fff;
            font-size: 11px;
            text-transform: uppercase;
            padding: 10px 15px;
            vertical-align: middle;
        }
        tbody tr:nth-child(even) {
            background: #f0f0f2;
        }
            #CreationDate {
            font-family: Arial, Helvetica, sans-serif;
            color: #ff3300;
            font-size: 12px;
        }
    </style>
"@
$addomain = (Get-ADDomainController | select Domain).Domain

Add-Content -Value "<html>" -Path Report_$guid.html
Add-Content -Value "<title>AD Scanner</title>" -Path Report_$guid.html
Add-Content -Value "<H1>AD Scanner Report</H1>" -Path Report_$guid.html
Add-Content -Value "<H3>Author     : Binu Balan</H3>" -Path Report_$guid.html
Add-Content -Value "<H3>Version    : $version </H3>" -Path Report_$guid.html
Add-Content -Value "<H3><i>Running Query against Domain -</B> $addomain </B></i></H3>" -Path Report_$guid.html
Add-Content -Value "<p><p>" -Path Report_$guid.html

Add-Content -Value "$header" -Path Report_$guid.html

Import-Csv checkAdminRename_$guid.csv | ConvertTo-Html -head "<h2>Default Admin Account Rename</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv checkFSMODomain_$guid.csv | ConvertTo-Html -head "<h2>FSMO Roles [Domain Wide Roles]</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv checkFSMOForest_$guid.csv | ConvertTo-Html -head "<h2>FSMO Roles [Forest Wide Roles]</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii

Import-Csv checkPasswordPolicy_$guid.csv | ConvertTo-Html -head "<h2>Account Lockout and Password Policy</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii

Import-Csv asrep_$guid.csv | ConvertTo-Html -head "<h2>ASREP Roast - Password Not Required</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv Kerberosting_$guid.csv | ConvertTo-Html -head "<h2>Kerberostable Account</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv PasswordNeverExpires_$guid.csv | ConvertTo-Html -head "<h2>Password Never Expires</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv SysvolPerm_$guid.csv | ConvertTo-Html -head "<h2>Sysvol Non-Default Permission</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv unexpectedFileShareOnAD_$guid.csv | ConvertTo-Html -head "<h2>Unexpected File Shares in AD</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv Netlogonperm_$guid.csv | ConvertTo-Html -head "<h2>Netlogon Non-Default Permission</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv RootHiddendelegate_$guid.csv | ConvertTo-Html -head "<h2>Root Hidden Delegation</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv SMBNull_$guid.csv | ConvertTo-Html -head "<h2>SMB Null Session</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv ServiceAcct_$guid.csv | ConvertTo-Html -head "<h2>Service Account</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv GetPatchStatus_$guid.csv | ConvertTo-Html -head "<h2>Last 3 OS Patch Status on AD</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv DomainAdmins_$guid.csv | ConvertTo-Html -head "<h2>Domain Admin Lists</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv LLMR_NetBIOS_$guid.csv | ConvertTo-Html -head "<h2>LLMNR / NETBIOS / MDNS Enablement Status</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv DefaultOUUGC_$guid.csv | ConvertTo-Html -head "<h2>Default Users under Root OU - cn=users </h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv AntivirusStatus_$guid.csv | ConvertTo-Html -head "<h2>Antivirus Status</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv UnconstraintDelegation_User_$guid.csv | ConvertTo-Html -head "<h2>Unconstraint User Delegation</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv UnconstraintDelegation_Comp_$guid.csv | ConvertTo-Html -head "<h2>Unconstraint Computer Delegation</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv TrustedforDelegation_user_$guid.csv | ConvertTo-Html -head "<h2>User Trusted for Delegation</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv TrustedforDelegation_Comp_$guid.csv | ConvertTo-Html -head "<h2>Computer Trusted for Delegation</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv DCSyncAccess_$guid.csv | ConvertTo-Html -head "<h2>DCSync Access Enabled IDs</h2><p><h3>Check if these users have excess permission as they have ObjectType value as 00000000-0000-0000-0000-000000000000<p> This could be Read All or Generic All too.</h3>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv dumpntds_$guid.csv | ConvertTo-Html -head "<h2>Users Having Acces to Dump NTDS.DIT</h2><p><h3>Members of Server Operator, Backup Operator, Administrators.</h3>" | Out-File Report_$guid.html -Append -Encoding Ascii
Import-Csv GPOChangeAccess_$guid.csv | ConvertTo-Html -head "<h2>Users Having Access to Modify GroupPolicy</h2><p><h3>Default permissions set for GPO are ignored.</h3>" | Out-File Report_$guid.html -Append -Encoding Ascii

Import-Csv ADDCList_$guid.csv | ConvertTo-Html -head "<h2>Users Having Access to Modify GroupPolicy</h2><p><h3>Default permissions set for GPO are ignored.</h3>" | Out-File Report_$guid.html -Append -Encoding Ascii


Add-Content -Value "</html>" -Path Report_$guid.html
}

Report $guid

$ErrorActionPreference = "Continue"

start .\Report_$guid.html
