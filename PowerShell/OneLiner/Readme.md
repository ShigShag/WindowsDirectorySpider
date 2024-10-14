# Powershell One Liner

Steps to execute the one liner

```powershell
# Create the one liner script
PS> ./ps1_to_cmd.ps1

# Set env variables, all are OPTIONAL if not set script will start in current directory
PS> $env:DirectoryPath="C:\Path\To\Dir"
PS> $env:OutputPath="metadata.json"
PS> $env:Include=@(".exe", ".txt")
PS> $env:Exclude=@(".pdf")

# Execute the script or copy the contents of Script.cmd to clipboard
PS> ./Script.cmd
```