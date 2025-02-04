# Run this as administrator
#
# PowerShell sucks, so clean up the output before commiting to Git repo:
# dos2unix service-dlls.txt
#   - UTF-16LE with BOM -> UTF-8 (no BOM, unlike the PowerShell "utf8" option, which has BOM) and CRLF -> LF
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\*\Parameters | Where-Object { $_.ServiceDll } | Select-Object -ExpandProperty ServiceDll | Out-File -FilePath "service-dlls.txt" -NoNewline
