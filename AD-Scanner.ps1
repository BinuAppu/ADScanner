# Appu - AD Health checker

$Logo = "
                                              
    ___    ____     _____                                 
   /   |  / __ \   / ___/_________ ____  ____  ___  _____
  / /| | / / / /   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ___ |/ /_/ /   ___/ / /__/ /_/ / / / / / / /  __/ /    
/_/  |_/_____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                       

==============================================
Author  : Binu Balan
Version : 1.0
==============================================
"

Import-Module ActiveDirectory | Out-Null

$Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@

function checkuserperm() {

    Write-Host " [+] Running in Domain Admin & Powershell with Admin context :" -ForegroundColor Green -NoNewline

    $modulechk = (Get-Module -ListAvailable -Name ActiveDirectory).Name
    if ($modulechk -eq "ActiveDirectory") {
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
        # Write-Host "[PASSED]" -ForegroundColor Green
    }
    else {
        # Write-Host "[FAILED]" -ForegroundColor Yellow
        Write-Host " You Must have following pre-requisite fullfilled for this script to run:
        1. Powershell Active Directory Module.
        2. Run PowerShell as Admin 
        3. User must be part of Domain Admins Group"
        Exit
    }

}


Function asrep($guid) {
    Write-Host " [+] AS-REP Query" -ForegroundColor Green
    Get-ADUser -LDAPFilter '(&(&(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))))' | Export-Csv -NoTypeInformation asrep_$guid.csv | Out-Null
}

Function Kerberosting($guid) {
    Write-Host " [+] Keberosting Query" -ForegroundColor Green
    Get-ADUSer -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName | Export-Csv -NoTypeInformation kerberosting_$guid.csv | Out-Null
}

Function PasswordNeverExpires($guid) {
    Write-Host " [+] Password Never Expires Query" -ForegroundColor Green
    get-aduser -filter * -properties Name, PasswordNeverExpires | where { $_.passwordNeverExpires -eq "true" } | Export-Csv -NoTypeInformation PasswordNeverExpires_$guid.csv | Out-Null
}

Function SysvolPerm($guid) {
    Write-Host " [+] AD Sysvol Permission Check" -ForegroundColor Green
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
    Write-Host " [+] AD Netlogon Permission Check" -ForegroundColor Green
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
    Write-Host " [+] Unexpected File Share detection on AD" -ForegroundColor Green
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
    Write-Host " [+] Checking Delegate access for Domain Root" -ForegroundColor Green
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
    Write-Host " [+] Fetching AD Service Account" -ForegroundColor Green  
    Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToDelegateToAccount, PrincipalsAllowedToRetrieveManagedPassword | select DistinguishedName, Enabled, Name, SamAccountName, @{name = "PrincipalsAllowedToDelegateToAccount"; expression = { $_.PrincipalsAllowedToDelegateToAccount -join "; " } }, @{name = "PrincipalsAllowedToRetrieveManagedPassword"; expression = { $_.PrincipalsAllowedToRetrieveManagedPassword -join "; " } } | Export-Csv -NoTypeInformation -Append ServiceAcct_$guid.csv
}

function SMBNull($guid) {
    Write-Host " [+] Anonymous AD enumeration check" -ForegroundColor Green
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

<<<<<<< HEAD
function GetPatchStatus($guid) {
    Write-Host " [+] Getting last 3 Patch install details from server." -ForegroundColor Green
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)
    foreach ($dc in $allDC) {
        Get-Hotfix -ComputerName $dc | Sort-Object -Property InstalledOn -Descending | Select-Object -First 3 | Export-Csv -Append -NoTypeInformation -Path GetPatchStatus_$guid.csv
    }
}
=======
function GetPatchStatus($guid){
    Write-Host " [+] Getting last 3 Patch install details from server." -ForegroundColor Green
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)
    foreach($dc in $allDC){
        Get-Hotfix -ComputerName $dc | Sort-Object -Property InstalledOn -Descending | Select-Object -First 3 | Export-Csv -Append -NoTypeInformation -Path GetPatchStatus_$guid.csv
    }
}
>>>>>>> f925ab31fd27cac23034b7fc084913342c826528

<<<<<<< HEAD
function DomainAdmins($guid) {
    Write-Host " [+] Getting Domain Admins User lists" -ForegroundColor Green
    Get-ADGroupMember "Domain Admins" -Recursive | Export-Csv -Append -NoTypeInformation -Path DomainAdmins_$guid.csv
}
=======
function DomainAdmins($guid){
    Write-Host " [+] Getting Domain Admins User lists" -ForegroundColor Green
    Get-ADGroupMember "Domain Admins" -Recursive | Export-Csv -Append -NoTypeInformation -Path DomainAdmins_$guid.csv
}
>>>>>>> f925ab31fd27cac23034b7fc084913342c826528

<<<<<<< HEAD
function LLMR_NetBIOS($guid) {
    Write-Host " [+] Checking LLMNR, NetBIOS, MDNS status" -ForegroundColor Green
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
    Write-Host " [+] Checking user/group part of default CN=User Container" -ForegroundColor Green
    $DomainDN = (Get-ADDomain).DistinguishedName
    $userc = (Get-ADUser -SearchBase "CN=Users,$DomainDN" -Filter *).count
    $groupc = (Get-ADGroup -SearchBase "CN=Users,$DomainDN" -Filter *).count
    $contactc = ((Get-ADObject -Filter 'objectclass -eq "contact"' -SearchBase "CN=Users,$DomainDN").name).count
    Add-Content -Value "User , Group , contact " -Path DefaultOUUGC_$guid.csv
    Add-Content -Value "$userc , $groupc , $contactc" -Path DefaultOUUGC_$guid.csv
}

=======
function LLMR_NetBIOS($guid){
    Write-Host " [+] Checking LLMNR, NetBIOS, MDNS status" -ForegroundColor Green
    # Add-Content -Value "----- Below list of AD allows Anonymous Access to AD ---- " -path anonymousSharesSAM_$Guid.csv
    $allDC = ((Get-ADDomain).ReplicaDirectoryServers)
    # Netbios

    ForEach ($dc in $allDC) {
            
        $nb = Invoke-Command -ScriptBlock { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces\tcpip_*' -Name NetBiosOptions).NetBiosOptions } -ComputerName $dc  # 0
        
        foreach($nbv in $nb){
            if($nbv -ne 0){
                Add-Content -Value " $dc , NetBIOSOverTCP is Enabled" -path LLMR_NetBIOS_$guid.csv
            }
        }

        $mdns = Invoke-Command -ScriptBlock { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS).EnableMDNS } -ComputerName $dc  # 0
       
        if($mdns -ne 0 -or $error){
            Add-Content -Value " $dc , MDNS is Enabled" -path LLMR_NetBIOS_$guid.csv
        }
        $error.Clear()

        $llmnr = Invoke-Command -ScriptBlock { (Get-ItemProperty -Path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast).EnableMulticast } -ComputerName $dc  # 0

        if($llmnr -ne 0 -or $error){
            Add-Content -Value " $dc , LLMNR is Enabled" -path LLMR_NetBIOS_$guid.csv
        }
        $error.Clear()

    }
    
}

>>>>>>> f925ab31fd27cac23034b7fc084913342c826528
cls
$ErrorActionPreference = "SilentlyContinue"
$FormatEnumerationLimit = -1
$guid = New-Guid 
$logo
checkuserperm
asrep $guid
Kerberosting $guid
PasswordNeverExpires $guid
SysvolPerm $guid
unexpectedFileShareOnAD $guid
Netlogonperm $guid
RootHiddendelegate $guid
SMBNull $guid
ServiceAcct $guid
<<<<<<< HEAD
GetPatchStatus $guid
DomainAdmins $guid
LLMR_NetBIOS $guid
DefaultOUUGC $guid
=======
GetPatchStatus $guid
DomainAdmins $guid
LLMR_NetBIOS $guid
>>>>>>> f925ab31fd27cac23034b7fc084913342c826528


# LDAPport $guid
<<<<<<< HEAD
=======



>>>>>>> f925ab31fd27cac23034b7fc084913342c826528
# OUHiddenDelegate $guid

<<<<<<< HEAD
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
Add-Content -Value "<html> $header" -Path Report_$guid.html
=======
$ErrorActionPreference = "Continue"
>>>>>>> f925ab31fd27cac23034b7fc084913342c826528

Add-Content -Value "<H1>AD Scanner Report</H1>" -Path Report_$guid.html
Import-Csv asrep_$guid.csv | ConvertTo-Html -head "<h2>ASREP Roast</h2>" | Out-File Report_$guid.html -Append -Encoding Ascii
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

Add-Content -Value "</html>" -Path Report_$guid.html
}

Report $guid

$ErrorActionPreference = "Continue"
