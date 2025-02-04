$processName = "svchost"

$processes = Get-Process
$searchCount = ($processes | Where-Object { $_.ProcessName -eq $processName }).Count
$totalCount = $processes.Count
Write-Host "$processName processes: $searchCount / $totalCount = " ($searchCount / $totalCount)
