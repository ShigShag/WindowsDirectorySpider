```powershell
NAME
    C:\Users\leonw\Downloads\WindowsDirectorySpider\PowerShell\dirspider.ps1

ÜBERSICHT
    Script to parse directories recursiv and save file metadata in json format.


SYNTAX
    C:\Users\leonw\Downloads\WindowsDirectorySpider\PowerShell\dirspider.ps1 [-DirectoryPath] <String> [[-OutputPath] <String>] [[-Include] <String[]>] [[-Exclude] <String[]>]
    [<CommonParameters>]


BESCHREIBUNG
    - Requires a DirectoyPath as a base path for the spidering process. The output path is optional, but should (but does not have to) point to a .json file.
    - The .json file will be filled in the process. Exiting the program early will result in an invalid .json format, which can be fixed by
    removing the trailing command and adding a closing bracket "]" at the end of the file
    - The script can include and exclude file types separately or at the same time.
    - By default .lnk files are followed to inspect the file behind the .lnk file.
    - This script uses very little memory, regardless of the size of the underlying file system.


PARAMETER
    -DirectoryPath <String>
        The base path to be parsed recursive.

    -OutputPath <String>
        Optional -> Default metadata.json
        The output path for the .json file which receives the metadata

    -Include <String[]>
        Extension(s) to include. Setting this will exclude all other Extensions. Must be set commad separated and with a leading dot before the extensions

    -Exclude <String[]>
        Extension(s) to exclude. Setting this will exclude this extensions no matter if Include is set or not.
        Must be set commad separated and with a leading dot before the extensions

    <CommonParameters>
        Dieses Cmdlet unterstützt folgende allgemeine Parameter: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable und OutVariable. Weitere Informationen finden Sie unter
        "about_CommonParameters" (https:/go.microsoft.com/fwlink/?LinkID=113216).

    -------------------------- BEISPIEL 1 --------------------------

    PS C:\>dirspider.ps1 -DirectoryPath "C:\Path\To\Files"

    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -OutputPath "C:\Path\to\output.json"
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -Include .exe,.txt,.pdf
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -Exclude .iso
    dirspider.ps1 -DirectoryPath "C:\Path\To\Files" -Include .png -Exclude .jpg,.txt
    Get-help ./dirspider.ps1 -detailed
```