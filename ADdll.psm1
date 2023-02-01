# ADDLL which is loaded to memory no dlls written
# DLL from windows Server2019 SHA256 Hash: 04C3EB093EEA4343B6A4D0F8F9810743F09392DDB26EF130D64287DADFE72992
# Created with:
# [byte[]] $DLL = Get-Content -Encoding byte -path E:\XXXX\Microsoft.ActiveDirectory.Management.dll
# [System.IO.File]::WriteAllLines("E:\XXXX\dll.txt", ([string]$DLL))
[Byte[]] $DLLBytes = $Data -split ' '       
$Assembly = [System.Reflection.Assembly]::Load($DLLBytes)
Import-Module -Assembly $Assembly