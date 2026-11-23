function Move-AslBuildOutput {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$Directory
    )

    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        try {
            if ($Directory) { [IO.Directory]::Move($Source, $Destination) }
            else { [IO.File]::Move($Source, $Destination) }
            return
        }
        catch {
            # Only wait for Windows ERROR_SHARING_VIOLATION; never replace a destination.
            if ($_.Exception.GetBaseException().HResult -ne -2147024864 -or $deadline.ElapsedMilliseconds -ge 5000) {
                throw
            }
            Start-Sleep -Milliseconds 125
        }
    }
}
