# WindowsDirectorySpider

This repo includes three Directory Spider Versions for Windows:

- [Rust Implementation](DirectorySpider)
- [Powershell Implementation](PowerShell)
- [C# Implementation](fileindexernet4)

### Benchmarks

#### Windows Folder with `160.810` files - 38 Gb of data

Rust: 

```powershell
Measure-Command { .\target\release\DirectorySpider.exe -d C:\Windows }


Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 2
Milliseconds      : 479
Ticks             : 24799748
TotalDays         : 2,8703412037037E-05
TotalHours        : 0,000688881888888889
TotalMinutes      : 0,0413329133333333
TotalSeconds      : 2,4799748
TotalMilliseconds : 2479,9748
```

Powershell

```powershell
Measure-Command { .\dirspider.ps1 -DirectoryPath C:\Windows  }


Days              : 0
Hours             : 0
Minutes           : 3
Seconds           : 17
Milliseconds      : 793
Ticks             : 1977930855
TotalDays         : 0,00228927182291667
TotalHours        : 0,05494252375
TotalMinutes      : 3,296551425
TotalSeconds      : 197,7930855
TotalMilliseconds : 197793,0855
```

### TODOS

- Implement `.lnk` traverse for rust and powershell (directory)
- Powershell one liner