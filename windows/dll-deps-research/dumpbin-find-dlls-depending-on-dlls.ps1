# Dumpbin DLLs Depending on DLLs
#
# For each DLL in a file, search for DLLs that depend on it
# Allow PowerShell script: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#
# NOTE: This script only takes into account one dependency layer
# It will find the DLLs depending on a given DLL; however, it cannot find deeper dependencies such as a DLL depending on a DLL which then depends on the given DLL we are searching for

# Define the input file containing DLL file paths and the output directory
$inputFile = $env:USERPROFILE + "\Desktop\service-dlls.txt"
$outputDirectory = $env:USERPROFILE + "\Desktop\dlls-depending-on-service-dlls"

# Pre-processed Dumpbin output directory of all DLLs to scan
# Get this pre-processed data by running dumpbin-dir.ps1 first
# For us, this is all DLLs in C:\Windows\System32 (not including subdirectories)
$dumpbinAllOutputDirectory = $env:USERPROFILE + "\Desktop\dumpbin-imports"

Set-Location -Path $dumpbinAllOutputDirectory

# Create directory if it doesn't exist
New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null

$dumpbinOutput = Get-Item $dumpbinAllOutputDirectory

# Iterate through DLL files list
foreach ($inputLine in Get-Content $inputFile) {
    #$inputLine = "C:\Windows\System32\dhcpcsvc.dll"
    $queryDll = Get-Item $inputLine
    #Write-Host "Searching for DLLs with dependencies on: ${queryDll.FullName}..."

    # Search for DLLs importing given DLL name
    foreach ($dumpbinOutputLine in $dumpbinOutput) {
        # Output format: DLL depended on: DLL taking dependency
        # Regex is for getting basename so output doesn't include the .txt extension given to dumpbin-dir.ps1 output data files
        Select-String -Path * -Pattern "    $($queryDll.Name)$" | ForEach-Object { "$($_.Line.Trim()): $($_.Filename  -replace '\.[^.]+$')" }
    }
}
