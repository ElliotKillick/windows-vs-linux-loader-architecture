# Dumpbin Delay Loads program
#
# Allow PowerShell script: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#
# PowerShell sucks, so clean up the output before commiting to Git repo:
# dos2unix delay-loads.txt
#   - UTF-16LE with BOM -> UTF-8 (no BOM, unlike the PowerShell "utf8" option, which has BOM)

# Define the input directory containing DLL files and the program output file
$inputDirectory = "C:\Windows\System32"
$outputFile = $env:USERPROFILE + "\Desktop\delay-loads.txt"

# Dumpbin program path
$dumpbinPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.30.30705\bin\Hostx64\x64\dumpbin.exe"

# Create output file
New-Item -Path $outputFile -ItemType File -ErrorAction Stop | Out-Null

# Get all DLL files in the directory
$dllFiles = Get-ChildItem -Path $inputDirectory -Filter *.dll

# Iterate through DLL files
foreach ($file in $dllFiles) {
    # Run dumpbin on DLL file and output into a file named according to the DLL name
    $outputLines = & $dumpbinPath /dependents $file.FullName /nologo

    $delayLoadsIdx = $outputLines.IndexOf("  Image has the following delay load dependencies:")
    if ($delayLoadsIdx -eq -1) {
        continue
    }

    # Get delay loads for DLL
    $output = "${file} Delay Loads:`n"
    # Skip empty line after delay load message to get DLL list
    $dllsIdx = $delayLoadsIdx + 2
    for ($i = $dllsIdx; $i -lt $outputLines.Length; $i++) {
        $line = $outputLines[$i]

        # Look for next empty line marking the end of delay loads
        if ($line -eq "") {
            break
        }

        $output = $output + $line + "`n"
    }

    $output | Out-File -FilePath $outputFile -Append -NoNewline
}
