param(
    [string]$GhidraLocation = "",
    [switch]$Verbose = $False
)

if ($GhidraLocation -eq "")
{
    $GhidraLocation=$env:GHIDRA_INSTALL_DIR
}

if (-not $GhidraLocation)
{
    Write-Error "No gidra location specified. Use GHIDRA_INSTALL_DIR environment variable or pass -GhidraLocation parameter";
    return
}

$OriginalFolderLocation=$GhidraLocation
$OriginalFiles=$(Get-ChildItem -Path $OriginalFolderLocation -Filter *.jar -Recurse -File -Name)

$OriginalFiles | ForEach-Object {
    #$_
    $Directory=$(Split-Path $_)
    $File=$(Split-Path $_ -Leaf)
    if ($Directory -notlike "*lib")
    {
        if ($Verbose)
        {
            Write-Host "File $_ is not in lib folder"
        }

        return
    }

    $Directory=$(Split-Path $Directory)
    $ComponentName=$(Split-Path $Directory -Leaf)
    if ("${ComponentName}.jar" -ne $File)
    {
        if ($Verbose)
        {
            Write-Host "File $_ is not component file, skipping"
        }

        return
    }

    Write-Host "Compare $_"
    Add-Type -AN System.IO.Compression.FileSystem
    $zip1 = [IO.Compression.ZipFile]::OpenRead("$OriginalFolderLocation\$_")
    $zip2 = [IO.Compression.ZipFile]::OpenRead("${PWD}\$_")
    $names1 = $zip1.Entries.FullName | Where-Object { ($_ -ne "") -and ($_ -notlike "META-INF/*.kotlin_module") -and ($_ -notlike "*[Tt]est*") }
    $names2 = $zip2.Entries.FullName | Where-Object { ($_ -ne "") -and ($_ -notlike "META-INF/*.kotlin_module") -and ($_ -notlike "META-INF/maven/*") }
    #$counter = (diff $names1 $names2)
    $difference=$(Compare-Object $names1 $names2)
    if ($difference.Length -gt 0)
    {
        $difference | Format-Table
        #continue
    }

    $zip1.Dispose()
    $zip2.Dispose()
}

#$BaseLine=$(Get-ChildItem -Path C:\Users\kant\Downloads\ghidra_9.0_PUBLIC_20190228\ghidra_9.0 -Filter *.jar -Recurse -File -Name)