<#
.SYNOPSIS
    Script to parse directories recursiv and save file metadata in json format.
.DESCRIPTION
    - Requires a DirectoyPath as a base path for the spidering process. The output path is optional, but should (but does not have to) point to a .json file.
    - The .json file will be filled in the process. Exiting the program early will result in an invalid .json format, which can be fixed by
    removing the trailing command and adding a closing bracket "]" at the end of the file
    - The script can include and exclude file types separately or at the same time.
    - By default .lnk files are followed to inspect the file behind the .lnk file.
    - This script uses very little memory, regardless of the size of the underlying file system.
.PARAMETER DirectoryPath
    The base path to be parsed recursive.
.PARAMETER OutputPath
    Optional -> Default metadata.json
    The output path for the .json file which receives the metadata
.PARAMETER Include
    Extension(s) to include. Setting this will exclude all other Extensions. Must be set commad separated and with a leading dot before the extensions
.PARAMETER Exclude
    Extension(s) to exclude. Setting this will exclude this extensions no matter if Include is set or not.
    Must be set commad separated and with a leading dot before the extensions

.EXAMPLE
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" 
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -OutputPath "C:\Path\to\output.json"
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -Include .exe,.txt,.pdf
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -Exclude .iso
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -Include .png -Exclude .jpg,.txt
    Get-help ./dirspider.ps1 -detailed
.NOTES
    Author: Leon Weinmann
#>

# Script execution starts here
param (
    [Parameter(Mandatory = $true)]
    [string]$DirectoryPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string[]]$Include = @(),
    [string[]]$Exclude = @()
)

# Initialize an empty queue
$BasePathQueue = New-Object System.Collections.Queue            

# Hashset to save already visited paths
$VisitedPathsGlobal = New-Object System.Collections.Generic.HashSet[String]

# Hashet to store visited directories in this run | So same as above just for an individual run
$VisitedDirectoriesInWalk = New-Object System.Collections.Generic.HashSet[String]

# Set file counter
[uint64]$fileCounter = 0

if (!$PSBoundParameters.ContainsKey("DirectoryPath")) {
    Write-Error "Parameter 'DirectoryPath' is required."
    Exit
}

# Function to get file metadata
function Get-FileMetadata {
    param (
        [string]$FilePath
    )

    try {
        $file = Get-Item -Path $FilePath

        # Collect metadata for the file
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
        
        # Convert array to json format
        $jsonString = $metadataList | ConvertTo-Json

        # Add comma to fit in json format
        $jsonString = "$jsonString,"

        # Append json to output file
        # This way not all files must be saved in a buffer at once
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
    # Get path where shortcut is pointing to
    $obj = New-Object -ComObject WScript.Shell
    $link = $obj.CreateShortcut($FilePath)
    $LinkFilePath = $link.TargetPath
    
    $target = Get-Item -Path $LinkFilePath
    
    # Check if the target is a directory
    if (Test-Path -Path $target -PathType Container) {
        # Check if the directory is in scope of the current base path | If so ignore it
        if (!($target.FullName -like "$BasePath*")) {

            Write-Host "$FilePath Found lnk pointing to directory -> $target"
            $BasePathQueue.Enqueue($target)
        }
    }
    # If target is a file just add it as usual | This may created dublicates if this file is included in a .lnk directory
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

        # Convert array to json format
        $jsonString = $metadataList | ConvertTo-Json

        # Add comma to fit in json format
        $jsonString = "$jsonString,"

        # Append json to output file
        # This way not all files must be saved in a buffer at once
        $jsonString | Out-File -FilePath $OutputPath -Encoding utf8 -Append

        $global:fileCounter += 1
    }
}

function Invoke-Path {
    param (
        $BasePath,
        $file
    )

    # Check if file or folder was already processed
    $dirName = $file.DirectoryName

    if ($file.PSisContainer) {
        $dirName = $file.FullName
    }

    if (!$VisitedPathsGlobal.Contains($dirName)) {
        # Check for directory and save it
        if ($_.PSisContainer) {
            $VisitedDirectoriesInWalk.Add($file.FullName) | Out-Null
        }
        else {
            # Get metadata for file | $_ is the current value in the pipeline
            Get-FileMetadata -FilePath $file.FullName

            $global:fileCounter += 1

            # Check for .lnk
            if ($file.Extension -eq ".lnk") {
                Invoke-lnk -BasePath $BasePath -FilePath $file.FullName
            }
        }
    } 
}

# Function to prevent circular links (avoid endless loop)
function Get-FolderMetadata {
    param (
        [string]$dirPath
    )

    # Add the base path to visited paths
    $VisitedDirectoriesInWalk.Add($dirPath) | Out-Null

    try {
        # Get all files recursively | Pipe this into ForEach-Object in order to save memory
        # This below looks stupid but PowerShell cant do it any better
        if ($Include.Count -eq 0) {
            if ($Exclude.Count -eq 0) {
                # Check if no specific file extensions were provided and $Exclude is empty too
                Get-ChildItem -Path $dirPath -Force -Recurse | ForEach-Object {
                    Invoke-Path -BasePath $dirPath -File $_ 
                }
            }
            else {
                # Check if no specific file extensions were provided but $Exclude has some filters
                Get-ChildItem -Path $dirPath -Force -Recurse -File | Where-Object { ($Exclude -notcontains $_.Extension) } | ForEach-Object {
                    Invoke-Path -BasePath $dirPath -File $_ 
                }
            }
        }
        else {
            if ($Exclude.Count -eq 0) {
                # Check if $Include has some filters but $Exclude is empty
                Get-ChildItem -Path $dirPath -Force -Recurse -File | Where-Object { ($Include -contains $_.Extension) } | ForEach-Object {
                    Invoke-Path -BasePath $dirPath -File $_
                }
            }
            else {
                # Check if both $Include and $Exclude have filters to be applied
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

# Validate the directory path
if (-Not (Test-Path -Path $DirectoryPath -PathType Container)) {
    Write-Error "Directory path '$DirectoryPath' does not exist or is not a valid directory."
    exit
}

# Resolve output path
$OutputPath = Resolve-Path -Path $OutputPath

# Write an opening array to the beginning of the file
# As a workaround for adding json, fields seperatly
$Writer = [System.IO.StreamWriter]::new($OutputPath, $false)
$Writer.WriteLine("[")
$Writer.Close()

# Add passed Base Path to queue
$BasePathQueue.Enqueue($DirectoryPath)

# Loop through the queue
for (; $true; ) {
    
    # Check if the queue is empty 
    if ($BasePathQueue.Count -eq 0) {
        break
    }

    # Dequeue an item from the queue
    $basepath = $BasePathQueue.Dequeue()

    Write-Host "Start Parsing: $basepath"

    # Parse files in that base path
    Get-FolderMetadata -dirPath $basepath

    # Add the visited directories from that run to global visited
    $VisitedPathsGlobal = $VisitedPathsGlobal + $VisitedDirectoriesInWalk

    # Empty the temporary Walk hashset
    $VisitedDirectoriesInWalk.Clear()
}

# Open as io file to remove trailing comma from last entry
$Writer = [IO.File]::OpenWrite($OutputPath)

# Remove comma
$Writer.SetLength($writer.Length - 3)

# Goto the end of the file | Prevent console output since this prints the size of the file
$Writer.Seek(0, [IO.SeekOrigin]::End) | Out-Null

# Encode closing bracket
$closingBracket = [System.Text.Encoding]::UTF8.GetBytes("]")

# Write the closing bracket
$Writer.Write($closingBracket, 0, $closingBracket.Length)

# Close the writer
$Writer.Close()

Write-Host "Metadata of $global:fileCounter files has been saved to $OutputPath"

# Do this for powershell reasons, since otherwise it is persistet over executions
$global:fileCounter = 0
