Write-Host $env:DirectoryPath

if ( $null -eq $env:DirectoryPath ) {
    $DirectoryPath = Get-Location
} else {
    $DirectoryPath = $env:DirectoryPath
}

if ($null -eq $env:OutputPath) {
    $OutputPath = "metadata.json"
} else {
    $OutputPath = $env:OutputPath
}

if ($null -eq $env:Include) {
    $Include = @()
} else {
    $Include = $env:Include
}

if ($null -eq $env:Exclude) {
    $Exclude = @()
} else {
    $Exclude = $env:Exclude
}

$BasePathQueue = New-Object System.Collections.Queue            
$VisitedPathsGlobal = New-Object System.Collections.Generic.HashSet[String]
$VisitedDirectoriesInWalk = New-Object System.Collections.Generic.HashSet[String]
[uint64]$fileCounter = 0

function Get-FileMetadata {
    param (
        [string]$FilePath
    )

    try {
        $file = Get-Item -Path $FilePath
        $metadataList = [PSCustomObject]@{
            name          = $file.Name
            full_path     = $file.FullName
            extension     = $file.Extension
            size          = $file.Length
            creation_time = $file.CreationTime
            last_access   = $file.LastAccessTime
            last_write    = $file.LastWriteTime
            is_read_only  = $file.IsReadOnly
        }
        $jsonString = $metadataList | ConvertTo-Json
        $jsonString = "$jsonString,"

        $jsonString | Out-File -FilePath $OutputPath -Encoding utf8 -Append
    }
    catch {
        Write-Warning "Failed to retrieve metadata for $FilePath $_"
    }
}

function Invoke-lnk {
    param (
        [string]$BasePath,
        [string]$FilePath
    )
    $obj = New-Object -ComObject WScript.Shell
    $link = $obj.CreateShortcut($FilePath)
    $LinkFilePath = $link.TargetPath
    
    $target = Get-Item -Path $LinkFilePath
    
    if (Test-Path -Path $target -PathType Container) {
        if (!($target.FullName -like "$BasePath*")) {

            Write-Host "$FilePath Found lnk pointing to directory -> $target"
            $BasePathQueue.Enqueue($target)
        }
    }
    else {
        # Normal procedure | Mark originated from shortcut
        $metadataList = [PSCustomObject]@{
            name          = $target.Name
            full_path     = $target.FullName
            extension     = $target.Extension
            size          = $target.Length
            creation_time = $target.CreationTime
            last_access   = $target.LastAccessTime
            last_write    = $target.LastWriteTime
            is_read_only  = $target.IsReadOnly
        }
        $jsonString = $metadataList | ConvertTo-Json
        $jsonString = "$jsonString,"
        $jsonString | Out-File -FilePath $OutputPath -Encoding utf8 -Append

        $global:fileCounter += 1
    }
}

function Invoke-Path {
    param (
        $BasePath,
        $file
    )

    $dirName = $file.DirectoryName

    if ($file.PSisContainer) {
        $dirName = $file.FullName
    }

    if (!$VisitedPathsGlobal.Contains($dirName)) {
        if ($_.PSisContainer) {
            $VisitedDirectoriesInWalk.Add($file.FullName) | Out-Null
        }
        else {
            Get-FileMetadata -FilePath $file.FullName

            $global:fileCounter += 1
            if ($file.Extension -eq ".lnk") {
                Invoke-lnk -BasePath $BasePath -FilePath $file.FullName
            }
        }
    } 
}

function Get-FolderMetadata {
    param (
        [string]$dirPath
    )
    $VisitedDirectoriesInWalk.Add($dirPath) | Out-Null

    try {
        if ($Include.Count -eq 0) {
            if ($Exclude.Count -eq 0) {
                Get-ChildItem -Path $dirPath -Force -Recurse | ForEach-Object {
                    Invoke-Path -BasePath $dirPath -File $_ 
                }
            }
            else {
                Get-ChildItem -Path $dirPath -Force -Recurse -File | Where-Object { ($Exclude -notcontains $_.Extension) } | ForEach-Object {
                    Invoke-Path -BasePath $dirPath -File $_ 
                }
            }
        }
        else {
            if ($Exclude.Count -eq 0) {
                Get-ChildItem -Path $dirPath -Force -Recurse -File | Where-Object { ($Include -contains $_.Extension) } | ForEach-Object {
                    Invoke-Path -BasePath $dirPath -File $_
                }
            }
            else {
                Get-ChildItem -Path $dirPath -Force -Recurse -File | Where-Object { ($Include -contains $_.Extension) -and ($Exclude -notcontains $_.Extension) } | ForEach-Object {
                    Invoke-Path -BasePath $dirPath -File $_ 
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve contents for directory $dirPath $_"
    }
}

if (-Not (Test-Path -Path $DirectoryPath -PathType Container)) {
    Write-Error "Directory path '$DirectoryPath' does not exist or is not a valid directory."
    exit
}

$ScriptOutputPath = Resolve-Path -Path $OutputPath
$Writer = [System.IO.StreamWriter]::new($ScriptOutputPath, $false)
$Writer.WriteLine("[")
$Writer.Close()

$BasePathQueue.Enqueue($DirectoryPath)

for (; $true; ) {
    
    if ($BasePathQueue.Count -eq 0) {
        break
    }

    $basepath = $BasePathQueue.Dequeue()

    Write-Host "Start Parsing: $basepath"

    Get-FolderMetadata -dirPath $basepath

    $VisitedPathsGlobal = $VisitedPathsGlobal + $VisitedDirectoriesInWalk

    $VisitedDirectoriesInWalk.Clear()
}

$Writer = [IO.File]::OpenWrite($ScriptOutputPath)

$Writer.SetLength($writer.Length - 3)

$Writer.Seek(0, [IO.SeekOrigin]::End) | Out-Null

$closingBracket = [System.Text.Encoding]::UTF8.GetBytes("]")

$Writer.Write($closingBracket, 0, $closingBracket.Length)

$Writer.Close()

Write-Host "Metadata of $global:fileCounter files has been saved to $ScriptOutputPath"

$global:fileCounter = 0
