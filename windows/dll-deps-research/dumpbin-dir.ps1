# Dumpbin Directory program
#
# After dumping a directory of DLLs into separate per-DLL files, you can recursively grep through the output with grep -rin
# Allow PowerShell script: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Define the input directory containing DLL files and the dumpbin output directory
$inputDirectory = "C:\Windows\System32"
$outputDirectory = $env:USERPROFILE + "\Desktop\dumpbin-imports"

# Dumpbin program path
$dumpbinPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.30.30705\bin\Hostx64\x64\dumpbin.exe"
$dumpbinOption = "/imports" # "/imports", "/exports", etc.

# Create directory if it doesn't exist
New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null

# Get all DLL files in the directory
$dllFiles = Get-ChildItem -Path $inputDirectory -Filter *.dll

# Iterate through DLL files
foreach ($file in $dllFiles) {
    Write-Host "Processing ${file}..."
    # Run dumpbin on DLL file and output into a file named according to the DLL name
    & $dumpbinPath $dumpbinOption $file.FullName /out:$outputDirectory\$($file.BaseName).txt /nologo
}
