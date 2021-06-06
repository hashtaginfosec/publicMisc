Param(
   [Parameter(Position=1)]
   [string]$ComputerName
)


### Set DC Logo as desktop background
# Embed image file (dc-logo.jpg)
$b64='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'
$decodedFile=[System.Convert]::FromBase64String($b64)
Set-Content -Path "$($env:USERPROFILE)\dc-logo.jpg" -Value $decodedFile -Encoding Byte

# Add Interop Type Definition
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class Background { [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int SystemParametersInfo (Int32 uAction,Int32 uParam,String lpvParam,Int32 fuWinIni); }' | Out-Null

# Apply changes
[Background]::SystemParametersInfo(0x0014, 0, ($($env:USERPROFILE)+"\dc-logo.jpg"), (0x01 -bor 0x02))


# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

# Allow RDP through Windows Firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Rename the machine

if ($null -eq $ComputerName)
{
    [string]$ComputerName = "DigitalCrafts"
    Write-Host $ComputerName
}

Rename-Computer -NewName $ComputerName

# Clear Recent Files and Folders from Quick Access 
Remove-Item -Recurse -Force $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\*

# Clear PowerShell History
Clear-History

# Clear PSReadline History
Remove-Item (Get-PSReadlineOption).HistorySavePath

Exit
