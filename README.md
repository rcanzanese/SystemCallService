# SystemCallService

Host / process / thread-level system call tracer for Windows 7 / 8 / 2008 / 2012

## Prerequisites
* Requires .NET Framework 4.5 or newer
* Windows 7 / 2008 / 2008 R2 / 8 / 8.1 / 2012 / 2012 R2
* TraceEvent 1.0.29 (can be installed using Nuget)
* System.Data.SQLite 1.0.96.0 (can be installed using Nuget)

## Symbol tables
Symbol tables change when new kernel versions are released.
The current update process is manual and requires the Windows Debugging Tools.  
There is a tool in the utils/ directory to facilitate symbol lookup.

```
dbh.exe "kernel_file" enum | out-file "output symbols" -Encoding ASCII
```

## Quick start instructions

* Open an elevated command prompt or powershell by right clicking the icon and choosing "Run as Administrator"
* Change to the folder where SystemCallService.exe is located
* Install the service by running:
```
SystemCallService.exe -install 
```
* To uninstall the service, run:
```
SystemCallService.exe -uninstall
```

## Overview 

### Data storage

Data are stored in C:\Windows\Temp\system_call_service_data\
 * database.sqlite is a sqlite database containing all of the logged data.
 * debug_log.txt is a log file containing information useful for debugging.
 * host_data_trace is a binary file containing the host data
 * the *_trace files are the process and thread traces, with GUIDs specified in the database.sqlite

Major error messages are also logged to the Application Event Log.

### Usage
There are three ways to control the service.  All must be executed using "Run as Administrator":
* sc.exe
* SystemCallService.exe
* net.exe ()for stopping and starting the service only)

####Installation
```
sc.exe create SystemCallService binPath= "C:\Full\Path\To\SystemCallService.exe" start= auto
```
or
```
SystemCallService.exe -install 
```

####Uninstallation
```sc.exe delete SystemCallService```
or
```SystemCallService.exe -uninstall ```

####Start Logging

```sc.exe start SystemCallService```

or

```SystemCallService.exe -start ```

or

```net start SystemCallService```

####Stop Logging
```sc.exe stop SystemCallService```

or

```SystemCallService.exe -stop ```

or

```net stop SystemCallService```