# Get registered COM components (HKCR to include system-wide and per-user)
# Each COM class is a component
#
# PowerShell sucks, so clean up the output before commiting to Git repo:
# 1. dos2unix com-components.txt
#   - UTF-16LE with BOM -> UTF-8 and CRLF -> LF
# 2. sed -i 's/[[:space:]]*$//' com-components.txt
#   - Remove trailing spaces before each end of line
#   - Believe it or not, PowerShell includes a box of whitespace the size of your PowerShell window in the output. As a result, file size grows in large linear increments based on window size.
#
# Also, make sure your window is full sized when you run the command so entires aren't split between lines even though output is to a file (apparently isatty() doesn't exist on Windows?)
Get-ChildItem Registry::HKEY_CLASSES_ROOT\CLSID | Get-ItemProperty | Select-Object PsChildName, "(default)" | Out-File -FilePath "com-components.txt" -NoNewline
