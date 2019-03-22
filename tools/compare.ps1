param(
    [string]$GhidraLocation = "",
    [switch]$Verbose = $False,
    [switch]$Crc32Check = $False
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
    $entries1 = $zip1.Entries | Where-Object { 
        ($_.FullName -ne "") `
        -and ($_.FullName -notlike "META-INF/*.kotlin_module")`
        -and ($_.FullName -notlike "META-INF/MANIFEST.MF")`
        -and ($_.FullName -notlike "*[Tt]est*")
    }
    $entries2 = $zip2.Entries | Where-Object {
        ($_.FullName -ne "")`
        -and ($_.FullName -notlike "META-INF/*.kotlin_module")`
        -and ($_.FullName -notlike "META-INF/MANIFEST.MF")`
        -and ($_.FullName -notlike "*[Tt]est*")`
        -and ($_.FullName -notlike "META-INF/maven/*")
    }

    #$targetProperties="FullName","Length"
    $targetProperties="FullName"
    if ($Crc32Check)
    {
        $targetProperties="FullName","Length","Crc32"
    }
    
    $data1=$($entries1 | Select-Object $targetProperties | ConvertTo-Csv)
    $data2=$($entries2 | Select-Object $targetProperties | ConvertTo-Csv)
    $difference=$(Compare-Object $data1 $data2)
    if ($difference.Length -gt 0)
    {
        $difference | Format-Table
    }

    $zip1.Dispose()
    $zip2.Dispose()
}
