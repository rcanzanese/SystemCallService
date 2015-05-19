/* Copyright 2015 Ray Canzanese
 * email:  rcanzanese@gmail.com
 * url:    www.canzanese.com 
 *
 * This file is part of SystemCallService.
 *
 * SystemCallService is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * SystemCallService is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SystemCallService.  If not, see <http://www.gnu.org/licenses/>.
 */

// TODO items
// - break more functions out of the main class
// - figure out if there is a easy way to incorporate symbol lookup


// NOTE:  You must manually set / unset this variable for 32 / 64 bit builds
//#define X86


using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SQLite;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Timers;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace SystemCallService
{
    /// <summary>
    /// Class for the service, extends the base service class.  No actual functionality is here other than handling requests.  
    /// </summary>
    public partial class SystemCallService : ServiceBase
    {
        private Thread _thread; // Worker thread for running the service
        private SystemCallServiceLoop _scc; // System  call counter object
        private bool _isRunning; // Keeps track of whether it is running to handle power events

        /// <summary>
        /// Initialization and establishes that the SCS handles power events
        /// </summary>
        public SystemCallService()
        {
            InitializeComponent();
            CanHandlePowerEvent = true;
        }

        /// <summary>
        /// Handles hibernation events.
        /// </summary>
        /// <param name="powerStatus">Powerstatus passed in by SC</param>
        /// <returns>true</returns>
        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            EventLog.WriteEntry("Power Status Change -- " + powerStatus, EventLogEntryType.Warning);

            if (PowerBroadcastStatus.Suspend == powerStatus)
            {
                if (_isRunning)
                {
                    EventLog.WriteEntry("Stopping for suspend.", EventLogEntryType.Warning);
                    OnStop();
                }
                else
                {
                    EventLog.WriteEntry("Tried suspending but it was already stopped.", EventLogEntryType.Warning);
                }
            }

            // Start on resume.
            else if (PowerBroadcastStatus.ResumeSuspend == powerStatus ||
                     PowerBroadcastStatus.ResumeAutomatic == powerStatus)
            {
                if (_isRunning)
                {
                    EventLog.WriteEntry("Tried resuming, but already running.", EventLogEntryType.Warning);
                }
                else
                {
                    EventLog.WriteEntry("Resuming.", EventLogEntryType.Warning);
                    OnStart(null);
                }
            }
            return true;
        }


        /// <summary>
        /// Called by SC when the service is started.  Must return immediately.
        /// </summary>
        /// <param name="args">Passed by SC</param>
        protected override void OnStart(string[] args)
        {
            _isRunning = true;

            // Sets the event log source so we can find us the in the application log
            EventLog.Source = "SystemCallService";

            // Starts the worker thread that actually performs all the useful tasks
            _thread = new Thread(WorkerThreadFunc)
            {
                Name = "Main SystemCallService Worker Thread",
                IsBackground = true
            };
            _thread.Start();

            // Prints the path to the local configuration to the app event log.
            EventLog.WriteEntry(
                "Local Configuration Location:" +
                ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.PerUserRoamingAndLocal).FilePath,
                EventLogEntryType.Information);
        }

        /// <summary>
        /// Called by SC when service is stopped
        /// </summary>
        protected override void OnStop()
        {
            _isRunning = false;

            // Signal the thread to stop collecting data
            _scc.Stop(true);

            // Give the thread 10 seconds to stop gracefully.  It does a lot of processing, so we are conservative with this etimate for now. 
            if (_thread.Join(10000)) return;

            EventLog.WriteEntry("Internal error Stopping Service", EventLogEntryType.Error);
            _thread.Abort();
        }

        /// <summary>
        /// Worker thread responsible for kicking off the data collection.  Exits when the data collection is signalled by OnStop to stop.
        /// </summary>
        private void WorkerThreadFunc()
        {
            // Create a new SyscallCounter object with sampling periods from settings
            _scc = new SystemCallServiceLoop(EventLog);

            // Continuously restart the service until IsRunning is set to false
            while (_isRunning)
            {
                _scc.Start();
            }
        }
    }

    /// <summary>
    /// Put host, process, and thread metadata in a SQLite database
    /// </summary>
    public class DatabaseInterface
    {
        //EventLog object for logging to the Application Event Log
        private readonly StreamWriter _debugLog;

        // Database connection
        private readonly SQLiteConnection _connection;

        // Everything is in one transaction
        private SQLiteTransaction _transaction;

        // Queries for adding processes and threads and a list of the column titles to expedite the query building.
        private readonly SQLiteCommand _processAdd;
        private readonly List<string> _processColumns;
        private readonly SQLiteCommand _threadAdd;
        private readonly List<string> _threadColumns;
        private readonly SQLiteCommand _processEnd;
        private readonly SQLiteCommand _threadEnd;

        /// <summary>
        /// Constructor 
        /// </summary>
        /// <param name="path">Absolute path to the database file</param>
        /// <param name="debugLog">Handle to debug log</param>
        public DatabaseInterface(string path, StreamWriter debugLog)
        {
            _debugLog = debugLog;

            // Create file
            SQLiteConnection.CreateFile(path);

            //Connect and open handle 
            _connection = new SQLiteConnection("Data Source=" + path + ";Version=3;");
            _connection.Open();

            _transaction = _connection.BeginTransaction();

            // Create table for processes 
            using (SQLiteCommand genericCommand = _connection.CreateCommand())
            {
                // Create process Table 
                genericCommand.CommandText = "CREATE TABLE Processes (" +
                                             Properties.SystemCallServiceSettings.Default.ProcessTableStructure + ")";
                genericCommand.ExecuteNonQuery();
                _processAdd = SetupObjectQuery(typeof (ProcessInfo), "Processes", out _processColumns);

                // Create table for threads 
                genericCommand.CommandText = "CREATE TABLE Threads (" +
                                             Properties.SystemCallServiceSettings.Default.ThreadTableStructure + ")";
                genericCommand.ExecuteNonQuery();
                genericCommand.Dispose();
            }

            // Create command for thread and process endings 
            _threadEnd = _connection.CreateCommand();
            _threadEnd.CommandText = "UPDATE threads SET StopRelativeMsec=@StopRelativeMsec WHERE Guid=@Guid";
            _threadEnd.Parameters.AddWithValue("@StopRelativeMsec", "");
            _threadEnd.Parameters.AddWithValue("@Guid", "");

            _processEnd = _connection.CreateCommand();
            _processEnd.CommandText = "UPDATE processes SET StopRelativeMsec=@StopRelativeMsec WHERE Guid=@Guid";
            _processEnd.Parameters.AddWithValue("@StopRelativeMsec", "");
            _processEnd.Parameters.AddWithValue("@Guid", "");

            _threadAdd = SetupObjectQuery(typeof (ThreadInfo), "Threads", out _threadColumns);

            // Commit all the table creations and starts a new transaction
            _transaction.Commit();
            _transaction.Dispose();
            _transaction = _connection.BeginTransaction();
        }


        /// <summary>
        /// Update the thread end time.
        /// </summary>
        /// <param name="mSec">end time in ms</param>
        /// <param name="guid">thread guid</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void UpdateThreadEnd(double mSec, string guid)
        {
            _threadEnd.Parameters["@StopRelativeMsec"].Value = mSec;
            _threadEnd.Parameters["@Guid"].Value = guid;
            _threadEnd.ExecuteNonQuery();
        }

        /// <summary>
        /// Update the process end time.
        /// </summary>
        /// <param name="mSec">end time in ms</param>
        /// <param name="guid">process guid</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void UpdateProcessEnd(double mSec, string guid)
        {
            _processEnd.Parameters["@StopRelativeMsec"].Value = mSec;
            _processEnd.Parameters["@Guid"].Value = guid;
            _processEnd.ExecuteNonQuery();
        }

        /// <summary>
        /// Construct a query to use for adding properties of an object to the database.
        /// </summary>
        /// <param name="type">The object type that will be added</param>
        /// <param name="table">The name of the table</param>
        /// <param name="columns">Output the names of the columns so we don't have to look them up every time.</param>
        /// <returns>The sqlite command </returns>
        public SQLiteCommand SetupObjectQuery(Type type, string table, out List<string> columns)
        {
            columns = new List<String>();
            foreach (var field in type.GetProperties())
            {
                if (!field.Name.Contains("Flag") && !field.Name.Contains("InsertCommand"))
                    // I have flags in the data structures that are only used internally and not added to database
                {
                    columns.Add(field.Name);
                }
            }

            SQLiteCommand command = _connection.CreateCommand();
            command.CommandText = "INSERT INTO " + table + "(" + String.Join(",", columns) + ") VALUES(@" +
                                  String.Join(",@", columns) + ")";

            foreach (var column in columns)
            {
                command.Parameters.AddWithValue("@" + column, "");
            }

            return command;
        }

        /// <summary>
        /// Add the properties of an object as a new entry into the table.
        /// </summary>
        /// <param name="data">The object containing data to add</param>
        /// <param name="table">The name of the table</param>
        /// <param name="command">The command prepared by SetupObjectQuery</param>
        /// <param name="columns">The name of the columns prepared by SetupObjectQuery</param>
        /// <returns>True</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool AddObject(Object data, string table, SQLiteCommand command, List<string> columns)
        {
            foreach (var column in columns)
            {
                command.Parameters["@" + column].Value = data.GetType().GetProperty(column).GetValue(data, null);
            }
            command.ExecuteNonQuery();
            return true;
        }

        /// <summary>
        /// Add a thread to the thread table.
        /// </summary>
        /// <param name="thread"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool AddThread(ThreadInfo thread)
        {
            AddObject(thread, "Threads", _threadAdd, _threadColumns);
            return true;
        }

        /// <summary>
        /// Add a process to the process table.
        /// </summary>
        /// <param name="process"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool AddProcess(ProcessInfo process)
        {
            AddObject(process, "Processes", _processAdd, _processColumns);
            return true;
        }

        /// <summary>
        /// Add system information
        /// </summary>
        /// <param name="sysinfo">System information structure</param>
        /// <returns></returns>
        public bool AddSystemInformation(SystemInformation sysinfo)
        {
            using (var localCommand = _connection.CreateCommand())
            {
                //Create table
                localCommand.CommandText = "CREATE TABLE SystemInfo (" +
                                           Properties.SystemCallServiceSettings.Default.SystemInfoTableStructure + ")";
                localCommand.ExecuteNonQuery();

                // Setup Query 
                List<string> systemInfoColumns;
                SQLiteCommand systemInfoAdd = SetupObjectQuery(typeof (SystemInformation), "SystemInfo",
                    out systemInfoColumns);

                // Execute query 
                AddObject(sysinfo, "SystemInfo", systemInfoAdd, systemInfoColumns);
            }
            return true;
        }


        /// <summary>
        /// Commit the current transaction and create a new one.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Commit()
        {
            try
            {
                _transaction.Commit();
                _transaction.Dispose();
                _transaction = _connection.BeginTransaction();
            }
            catch (Exception e)
            {
                _debugLog.WriteLine("Commit error:  " + e);
            }
        }

        /// <summary>
        /// Commit transaction, dispose all commands, and close the connection to the database
        /// </summary>
        public void CloseConnection()
        {
            Commit();

            _processAdd.Dispose();
            _threadAdd.Dispose();
            _processEnd.Dispose();
            _threadEnd.Dispose();

            try
            {
                _transaction.Dispose();
            }
            catch (Exception e)
            {
                _debugLog.WriteLine("CloseError:  " + e);
            }
            try
            {
                _connection.Close();
                _connection.Dispose();
            }
            catch (Exception e)
            {
                _debugLog.WriteLine("CloseError:  " + e);
            }
        }
    }

    /// <summary>
    /// Generic class for storing information about a process or thread
    /// </summary>
    public class Info
    {
        public String Guid { get; set; } // GUID to identify the data table.
        public double DeletionFlag; // Indicates when object was flagged for deletion
        public bool Deleted; // Indicates that that it has been deleted
        public double StartRelativeMSec { get; set; } // Time the process started as RelativeMSec count
        public DateTime Start { get; set; } // Time the process was started
        public double StopRelativeMSec { get; set; } // Time the process started as RelativeMSec count
        public SystemCallTracer Counter; // Where the tracing and counting occurs
    }

    /// <summary>
    /// Information about active processes
    /// </summary>
    public class ProcessInfo : Info
    {
        public string Name; // Just the executable name
        public int Pid { get; set; }
        public long ProcessKey; // I don't know whether this is unique -- currently unused 
        public string CommandLine { get; set; } // Full path used to launch the process
        public string ImageFileName { get; set; } // Same as executable name?
        public string KernelImageFileName; // Same as executable name?
        public int ParentId { get; set; } // Parent PID
        public uint TotalThreads; // Total number of child threads
        public uint ActiveThreads; // Number of threads currently executing 
        public double LastActive; // Time it was last CSWITCHED off a core.
        public string Md5 { get; set; }
    }

    /// <summary>
    /// Information about the host
    /// </summary>
    public class SystemInformation
    {
        public string NtoskrnlVersion { get; set; } // ntoskrnl.exe file version
        public string NtoskrnlMd5 { get; set; } // ntoskrnl.exe file version
        public int Cores { get; set; } // Number of logical processor cores
        public string Hostname { get; set; } // hostname
        public double HostSampling { get; set; } // System sampling period
        public double ProcessSampling { get; set; } // Process sampling period
        public double ThreadSampling { get; set; } // Thread Sampling period
        public long HostTrace { get; set; } // System sampling period
        public long ProcessTrace { get; set; } // Process sampling period
        public long ThreadTrace { get; set; } // Thread Sampling period
    }

    /// <summary>
    /// Information about active threads
    /// </summary>
    public class ThreadInfo : Info
    {
        public int Pid { get; set; } // PID to which the thread belongs
        public double PidStartRelativeMSec { get; set; } // Process start time as RelativeMSec 
        public int Tid { get; set; }
        public String ProcessGuid { get; set; } // Process GUID so we can do joins
        public double LastActive; // Last time it was CSWITCHed out 
        public bool IsActive; // Whether it is currently active on a core
    }

    /// <summary>
    /// Perform system call traces at the host, process, and thread levels
    /// </summary>
    public class SystemCallTracer
    {
        private readonly string _filename;

        // TODO:  Implement these or remove them.
        private double _startTimeMs;
        private StreamWriter _debugLog;

        // For saving raw traces 
        private long _maxTrace = -1;
        private FileStream _traceOutputFile;
        private BinaryWriter _traceWriter;
        private bool _fullTrace;
        private long _traceLength;
        private bool _traceFinished = true;

        /// <summary>
        /// Create the tracer.
        /// </summary>
        /// <param name="filename">Filename to store the trace</param>
        /// <param name="debugLog">Debug logger</param>
        public SystemCallTracer(string filename, StreamWriter debugLog)
        {
            _filename = filename;
            _debugLog = debugLog;
        }



        /// <summary>
        /// Initialize a trace
        /// </summary>
        /// <param name="maxTrace">Maximum number of system calls.  Negative number indicates no limit.</param>
        /// <param name="timeMs">Start time of trace in ms.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void InitializeFullTrace(long maxTrace, double timeMs)
        {
            _traceOutputFile = File.Open(_filename + "_trace", FileMode.Create);
            _traceWriter = new BinaryWriter(_traceOutputFile);
            _maxTrace = maxTrace;
            _traceFinished = false;
            _fullTrace = true;
            _startTimeMs = timeMs;
        }

        /// <summary>
        /// Add a system call to the trace
        /// </summary>
        /// <param name="syscall">system call index</param>
        /// <param name="timeMs">time of the call</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Add(ushort syscall, double timeMs)
        {
            if (!_fullTrace) return;

            if (_maxTrace >= 0 && _traceLength >= _maxTrace)
            {
                if (_traceFinished) return;
                _traceFinished = true;
                _traceWriter.Flush();
                _traceWriter.Close();
                _traceOutputFile.Close();
                //DebugLog.WriteLine("TOTAL_TRACE_TIME=" + (time - StartTimeMs));
                return;
            }
            _traceWriter.Write(syscall);
            _traceLength += 1;
        }
        
        /// <summary>
        /// End the trace and close the file.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Close()
        {
            if (_traceFinished) return;
            _traceFinished = true;
            _traceWriter.Flush();
            _traceWriter.Close();
            _traceOutputFile.Close();
        }
    }

    /// <summary>
    /// Service loop and primary interface with ETW
    /// </summary>
    public class SystemCallServiceLoop
    {
        // Regex for sanitizing the command line -- either it is quoted, contains spaces and ends with exe, or contains no spaces.  This covers all cases seen on the development machine.
        private readonly Regex _pathRegex = new Regex("(\"[^\"]*\"|.*?\\.exe|[^ ]*)");

        // List of settings we want to print out in debug log / get from web
        private readonly string[] _properties =
        {
            "AutoResetMs", "TracePerProcess", "TracePerThread", "MaxTraceSyscalls",
            "Verbosity", "ScrubCommandLine", "AnonymizeHostname"
        };

        // Private copies of settings for speed.  I don't know whether these are actually faster.
        private readonly bool _traceHostLevel = Properties.SystemCallServiceSettings.Default.TraceHostLevel;
        private readonly bool _tracePerThread = Properties.SystemCallServiceSettings.Default.TracePerThread;
        private readonly bool _tracePerProcess = Properties.SystemCallServiceSettings.Default.TracePerProcess;
        private readonly long _maxTraceSyscalls = Properties.SystemCallServiceSettings.Default.MaxTraceSyscalls;
        private readonly int _verbosity = Properties.SystemCallServiceSettings.Default.Verbosity;
        private readonly double _commitInterval = Properties.SystemCallServiceSettings.Default.CommitInterval;
        private readonly bool _scrubCommandLine = Properties.SystemCallServiceSettings.Default.ScrubCommandLine;
        private readonly string _dataDirectory = Properties.SystemCallServiceSettings.Default.DataDirectory;
        private readonly double _processDeletionDelay = Properties.SystemCallServiceSettings.Default.ProcessDeletionDelay; //ms
        private readonly double _minBackoff = Properties.SystemCallServiceSettings.Default.MinBackoff;
        private double _threadDeletionDelay = Properties.SystemCallServiceSettings.Default.ThreadDeletionDelay; //ms 

        // Counting system call tuples
        private SystemCallTracer _systemWideCounter;

        // System call list 
        private List<string> _syscallNameList;

        //Code profiling
        private readonly bool _profileCode = Properties.SystemCallServiceSettings.Default.ProfileCode;
        private readonly Dictionary<String, Stopwatch> _codeProfileTimers = new Dictionary<String, Stopwatch>();
        private readonly Dictionary<String, ulong> _codeProfileCounters = new Dictionary<String, ulong>();

        private readonly string[] _codeProfileKeys =
        {
            "Commit", "Syscall", "ProcessStartTable", "WriteProcessData", "ProcessDeletionQueue", "ThreadDeletionQueue",
            "ContextSwitch", "ContextSwitch1", "ContextSwitch2", "ContextSwitch3", "Database.Commit",
            "WriteProcessDataInsert", "CreateTable", "WriteSystemData", "ProcessStart", "ProcessStop", "ThreadStart",
            "ThreadStop", "CreateCommand", "InsertCommandClone", "InsertCommandNew"
        };

        // Last time we checked for thread and process deletion
        private double _lastDeletionCheck;

        // System information
        private SystemInformation _systemInfo;

        // End service flag
        private bool _endService;

        // Timer to trigger automatic restarts
        private readonly System.Timers.Timer _resetTimer;

        // Database connection
        private DatabaseInterface _database;

        // For timing the code 
        private readonly Stopwatch _timer = new Stopwatch(); // Keeps track of processing lag.

        // For keeping track of how much time each thread has been active since last cswitch
        private double[] _lastCSwitch;
        
        // Dict for active threads, indexed by PID then TID
        private class ThreadDict : Dictionary<int, ThreadInfo>{}
        private class ProcessThreadDict : Dictionary<int, ThreadDict>{};

        //Queue for creating tables
        private readonly Queue<Info> _tableCreations = new Queue<Info>();

        // Queue for deleting processes and threads
        private readonly List<ProcessInfo> _processesToDelete = new List<ProcessInfo>();
        private readonly List<ThreadInfo> _threadsToDelete = new List<ThreadInfo>();

        // A Dictionary of active threads by process [PID][TID]
        private readonly ProcessThreadDict _activeThreadsByProcess = new ProcessThreadDict();

        // Dict for unknown threads, indexed by TID
        private readonly ThreadDict _unkownThreads = new ThreadDict();

        // Dict for active processes, indexed by PID
        private readonly Dictionary<int, ProcessInfo> _activeProcesses = new Dictionary<int, ProcessInfo>();

        //EventLog object for logging to the Application Event Log
        private readonly EventLog _eventLog;

        // Data directory location, used for generating paths to various files
        private readonly string _rootPath;
        private readonly string _tempPath;
        private string _dataSubFolder;

        // Maps from the addresses to some set of integers so we can do array indexing quickly and easily
        private int[] _ntMap;
        private ulong _ntLowestAddress;
        private ulong _ntMaxAddress;

        // Number of logical processors
        private int _logicalProcessorCount;

        // File to store all of our debug messages
        private StreamWriter _debugLog;

        // Event tracing session
        private TraceEventSession _eventTracingSession;

        // Place to keep track of what process and thread on each processor core
        private int[] _processorActiveThreads;
        private int[] _processorActiveProcesses;

        // Default values for processors. Used for convenience
        private const int DefaultProcessorValue = -2;
        private const int UnknownPid = -1;
        private const int IdlePid = 0;

        // Address of the Kenrel
        private UInt64 _ntKernelAddress;
        private String _ntKernelImageName;

        // Track the last time the database changes were committed
        private double _lastCommit = -100;

        // DLL imports for the functions that we use to get the base addresses of the kernel modules.
        // The precompiler directives handle the 32 bit vs. 64 distinction
        [DllImport("psapi")]
        private static extern bool EnumDeviceDrivers(
#if X86
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] UInt32[] ddAddresses,
#else
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In] [Out] UInt64[] ddAddresses,
#endif
            UInt32 arraySizeBytes,
            [MarshalAs(UnmanagedType.U4)] out UInt32 bytesNeeded
            );

        [DllImport("psapi")]
        private static extern int GetDeviceDriverBaseName(
#if X86
            UInt32 ddAddress,
#else
            UInt64 ddAddress,
#endif
            StringBuilder ddBaseName,
            int baseNameStringSizeChars
            );

        /// <summary>
        /// Set the tracer parameters.
        /// </summary>
        /// <param name="el">EventLog object</param>
        public SystemCallServiceLoop(EventLog el)
        {
            // Keep an instance variable of the event log -- used for crash logging
            _eventLog = el;

            // Keep track of where this is executing from and where we store the data
            _rootPath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
            _tempPath = Path.GetTempPath();

            // Setup a timer to automatically restart logging 
            _resetTimer = new System.Timers.Timer {AutoReset = false};
            _resetTimer.Elapsed += ResetTimerEvent;
        }

        /// <summary>
        /// Compute the MD5 of the kernel.
        /// </summary>
        /// <param name="kernelFileName">Filename of kernel (varies for different versions of wWndows).</param>
        /// <returns></returns>
        private string ComputeMd5(string kernelFileName)
        {
            string md5Sum;

            // Debug print MD5sum of the kernel
            using (var md5 = MD5.Create())
            {
                using (
                    var stream =
                        File.OpenRead(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                            kernelFileName)))
                {
                    md5Sum = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLower();
                }
            }
            return md5Sum;
        }

        /// <summary>
        /// Load the system call addresses.
        /// </summary>
        /// <param name="kernelFileName">Filename of the kernel</param>
        /// <param name="version">Kernel version</param>
        /// <param name="sensorFileName">Filename that lists desired system calls to trace</param>
        /// <param name="sensorList">List of the system calls (out)</param>
        /// <param name="baseAddress">Base address of kernel (out)</param>
        /// <param name="maxAddress">Max address of system call (out)</param>
        /// <param name="indexBase">Used as offset for GDI tracing to prevent index collisions with multiple kernel files.</param>
        /// <param name="kernelBase">Base address of the kernel.</param>
        /// <returns>The map from addresses to indices</returns>
        private int[] LoadAddressMaps(String kernelFileName, String version, String sensorFileName,
            out List<string> sensorList, out ulong baseAddress, out ulong maxAddress, int indexBase, ulong kernelBase)
        {
            // Load the symbol table and build a dict, where the sensor names are the keys 
            string[] lines;
            string md5Sum = ComputeMd5(kernelFileName);
            _debugLog.WriteLine("KERNEL MD5: " + md5Sum);

            // This is an abuse of naming, but because they are identified by version and MD5, I am not going to differentiate among different kernel image file names
            string subdirectory = "ntoskrnl.exe";
            string localFilename = Path.Combine(_rootPath, Properties.SystemCallServiceSettings.Default.SymbolSubfolder,
                subdirectory, version + "_" + md5Sum + ".symbols");

            try
            {
                lines = File.ReadAllLines(localFilename);
            }
            catch
            {
                _debugLog.WriteLine("Kernel symbols not held locally.  Checking online");
                _debugLog.WriteLine("NtVersion: " + _systemInfo.NtoskrnlVersion);
                _debugLog.WriteLine("Local Filename: " + localFilename);
                _debugLog.Flush();

                File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), kernelFileName),
                        Path.Combine(_tempPath, Properties.SystemCallServiceSettings.Default.DataDirectory,
                        _dataSubFolder, version + "_" + md5Sum + ".binary"));
                maxAddress = 0;
                baseAddress = 0;
                sensorList = null;
                return null;
            }

            Dictionary<string, UInt64> symbolTable = new Dictionary<string, UInt64>();

            // First group is the address, second group is the name;
            Regex re = new Regex(@"[ ]+[0-9a-f]+[ ]+([0-9a-f]+)[ ]+:+[ ]+(.*)");

            foreach (string line in lines)
            {
                Match match = re.Match(line);

                if (match.Success)
                {
                    symbolTable[match.Groups[2].Value] = UInt64.Parse(match.Groups[1].Value, NumberStyles.HexNumber) -
                                                         UInt64.Parse("1000000", NumberStyles.HexNumber);
                    // corrects dbh.exe offset default.
                }
            }

            // Load the sensor list to figure out the offsets
            lines = File.ReadAllLines(Path.Combine(_rootPath, sensorFileName));

            // Creates a list of the sensor names as a list of strings and the map from the addresses to the indices
            sensorList = new List<string>();

            List<UInt64> temp = new List<UInt64>();

            // Convert the list of addresses to a map.
            foreach (string line in lines)
            {
                sensorList.Add(line);
                try
                {
                    var offset = symbolTable[line];
                    temp.Add(offset);
                }
                catch
                {
                    _debugLog.WriteLine("Sensor not found in symbol table:  " + line);
                }
            }

            baseAddress = temp.Min() + kernelBase;
            maxAddress = temp.Max() + kernelBase;
            int[] sensorMap = new int[1 + (temp.Max() - temp.Min())];

            for (int i = 0; i < sensorMap.Count(); i++)
            {
                sensorMap[i] = -1;
            }

            for (int i = 0; i < temp.Count; i++)
            {
                sensorMap[(temp[i] - temp.Min())] = i + indexBase;
            }

            // Debugging information
            _debugLog.WriteLine("Base:  {0:X}", kernelBase);
            _debugLog.WriteLine("Min:  {0:X}", temp.Min());
            _debugLog.WriteLine("Max:  {0:X}", temp.Max());
            _debugLog.WriteLine("baseAddress:  {0:X}", baseAddress);
            _debugLog.WriteLine("maxAddress:  {0:X}", maxAddress);

            return sensorMap;
        }

        /// <summary>
        /// Get the hostname or the anonymized identifier. 
        /// </summary>
        /// <returns>hostname or anonymized identifier</returns>
        private string GetHostname()
        {
            string hostname;
            if (Properties.SystemCallServiceSettings.Default.AnonymizeHostname)
            {
                if (Properties.SystemCallServiceSettings.Default.HostIdentifier == "None")
                {
                    Properties.SystemCallServiceSettings.Default.HostIdentifier = Path.GetRandomFileName();
                    Properties.SystemCallServiceSettings.Default.Save();
                }
                hostname = Properties.SystemCallServiceSettings.Default.HostIdentifier;
            }
            else
            {
                hostname = Environment.MachineName;
            }
            return hostname;
        }


        /// <summary>
        /// Ges system information and save it in the database
        /// </summary>
        private void GetSystemInformation()
        {
            // Anonymize the hostname (if necessary) by generating random string instead and saving it in properties
            string hostname = GetHostname();


            // Creates object to hold system info and populates it
            _systemInfo = new SystemInformation
            {
                Cores = Environment.ProcessorCount,
                NtoskrnlVersion =
                    FileVersionInfo.GetVersionInfo(
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), _ntKernelImageName))
                        .ProductVersion,
                NtoskrnlMd5 = ComputeMd5(_ntKernelImageName),
                Hostname = hostname,
                ThreadSampling = 0,
                ProcessSampling = 0,
                HostSampling = 0,
                ThreadTrace = 0,
                ProcessTrace = 0,
                HostTrace = 0
            };

            if (Properties.SystemCallServiceSettings.Default.TracePerThread)
            {
                _systemInfo.ThreadTrace = Properties.SystemCallServiceSettings.Default.MaxTraceSyscalls;
            }
            if (Properties.SystemCallServiceSettings.Default.TracePerProcess)
            {
                _systemInfo.ProcessTrace = Properties.SystemCallServiceSettings.Default.MaxTraceSyscalls;
            }
            if (Properties.SystemCallServiceSettings.Default.TraceHostLevel)
            {
                _systemInfo.HostTrace = 1;
            }

            // Save logical processor count because we use it during tracing
            _logicalProcessorCount = _systemInfo.Cores;

            // Add to database
            _database.AddSystemInformation(_systemInfo);
        }


        /// <summary>
        /// Wrapper for regular starts.
        /// </summary>
        /// <param name="data">data from trace event</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessStart(TraceEvent data)
        {
            ProcessStartHelper(data, false);
        }

        /// <summary>
        /// Wrapper for dc starts.
        /// </summary>
        /// <param name="data">data from trace event</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessDcStart(TraceEvent data)
        {
            ProcessStartHelper(data, true);
        }

        /// <summary>
        /// Get the full path of anexecutable image.
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns>the path</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GetFullPath(string fileName)
        {
            // Trim surrounding quotes
            string path = fileName.Trim('\"');

            // If it already exists, just return it.
            if (File.Exists(path))
                return Path.GetFullPath(path);

            // If there isn't a dot, try adding an extension
            if (!path.Contains('.'))
            {
                path = path + ".exe";
                if (File.Exists(path))
                    return Path.GetFullPath(path);
            }

            // If there is a %, try expanding environment variables
            // If there isn't a dot, try adding an extension
            if (path.Contains('%'))
            {
                path = Environment.ExpandEnvironmentVariables(path);
                if (File.Exists(path))
                    return Path.GetFullPath(path);
            }

            // This appears at the beginning of some strings
            if (path.Contains(@"\??\"))
            {
                path = path.Replace(@"\??\", "");
                if (File.Exists(path))
                    return Path.GetFullPath(path);
            }

            // If there aren't any slashes, check the environment PATH
            if (!path.Contains(@"\"))
            {
                var values = Environment.GetEnvironmentVariable("PATH");
                if (values == null) return null;
                foreach (var t in values.Split(';'))
                {
                    var fullPath = Path.Combine(t, fileName);
                    if (File.Exists(fullPath))
                        return fullPath;
                }
            }

            return null;
        }


        /// <summary>
        /// When a process starts, add the process and the information about the process to the active processes dict and create a dict of threads for the process
        /// </summary>
        /// <param name="data">The trace event data</param>
        /// <param name="dcStart">True if a DC start</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessStartHelper(TraceEvent data, bool dcStart)
        {
            if (_profileCode)
            {
                _codeProfileCounters["ProcessStart"] += 1;
                _codeProfileTimers["ProcessStart"].Start();
            }

            ProcessTraceData procData = (ProcessTraceData) data;

            // We don't care about the system idle service.  We know it is there and that it does nothing.
            if (procData.ProcessID == IdlePid)
            {
                if (_profileCode)
                {
                    _codeProfileTimers["ProcessStart"].Stop();
                }
                return;
            }

            // Scrub command line -- take away the arguments 
            String commandLine;
            String scrubbedCommandLine;
            Match m = _pathRegex.Match(procData.CommandLine);
            if (m.Success)
            {
                scrubbedCommandLine = m.Value;
            }
            else
            {
                scrubbedCommandLine = "";
            }

            if (_scrubCommandLine)
            {
                commandLine = scrubbedCommandLine;
            }
            else
            {
                commandLine = procData.CommandLine;
            }

            // checksum the image if possible.  Checks existence first to avoid unnecessary error handling overhead.
            string md5Sum = "";
            if (!dcStart)
            {
                try
                {
                    string actualPath = GetFullPath(scrubbedCommandLine);

                    if (actualPath != null)
                    {
                        using (
                            FileStream fs = new FileStream(actualPath, FileMode.Open, FileAccess.Read,
                                FileShare.ReadWrite))
                        {
                            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
                            {
                                byte[] hash = md5.ComputeHash(fs);
                                StringBuilder buf = new StringBuilder(2*hash.Length);
                                foreach (byte b in hash)
                                {
                                    buf.AppendFormat("{0:X2}", b);
                                }
                                md5Sum = buf.ToString();
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    _debugLog.WriteLine("ERROR on " + scrubbedCommandLine);
                    _debugLog.WriteLine(e);
                }
            }

            //Create the process info struct
            ProcessInfo newProcess = new ProcessInfo
            {
                Name = data.ProcessName,
                Pid = data.ProcessID,
                ProcessKey = (long) procData.UniqueProcessKey,
                CommandLine = commandLine,
                ImageFileName = procData.ImageFileName,
                KernelImageFileName = procData.KernelImageFileName,
                ParentId = procData.ParentID,
                Start = data.TimeStamp,
                StartRelativeMSec = data.TimeStampRelativeMSec,
                Guid = Guid.NewGuid().ToString("N"),
                Counter = null,
                Md5 = md5Sum
            };

            // Write a debug message indicating that a new process started
            if (_verbosity >= 3)
            {
                _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + " " + "Process Start:" + newProcess.Name +
                                    " " + newProcess.CommandLine + " " + newProcess.Pid);
            }

            // If we already Have the PID in the active process lists but it has been marked for deletion, lets try to force the deletion.  
            if (_activeProcesses.ContainsKey(data.ProcessID))
            {
                if (_verbosity >= 1)
                {
                    _debugLog.WriteLine("WARNING:  Process ID already exists.  " + data.ProcessID);
                    _debugLog.WriteLine("Deletion flag:  " + _activeProcesses[data.ProcessID].DeletionFlag);
                }

                if (_activeProcesses[data.ProcessID].DeletionFlag > 0)
                {
                    foreach (var thread in _activeThreadsByProcess[data.ProcessID])
                    {
                        thread.Value.DeletionFlag = data.TimeStampRelativeMSec - (_threadDeletionDelay*2);
                    }
                    _activeProcesses[data.ProcessID].DeletionFlag = data.TimeStampRelativeMSec -
                                                                    (_processDeletionDelay*2);

                    ThreadDeletionQueue(data);
                    ProcessDeletionQueue(data);

                    if (_activeProcesses.ContainsKey(data.ProcessID))
                    {
                        _debugLog.WriteLine("Error:  Process ID already exists.  " + data.ProcessID);
                        _debugLog.WriteLine("Deletion flag:  " + _activeProcesses[data.ProcessID].DeletionFlag);
                        throw new Exception("Duplicate process disaster despite our correction efforts");
                    }
                }
            }

            // Add Process to active process list
            _activeProcesses[data.ProcessID] = newProcess;

            // Add Process to active threads list
            _activeThreadsByProcess[data.ProcessID] = new ThreadDict();

            // Create a new tracker
            newProcess.Counter =
                new SystemCallTracer(Path.Combine(_tempPath, _dataDirectory, _dataSubFolder, newProcess.Guid), _debugLog);
            if (!dcStart && (_tracePerProcess))
            {
                newProcess.Counter.InitializeFullTrace(_maxTraceSyscalls, data.TimeStampRelativeMSec);
            }

            // Add to database
            if (_profileCode)
            {
                _codeProfileCounters["CreateTable"] += 1;
                _codeProfileTimers["CreateTable"].Start();
            }

            _database.AddProcess(newProcess);

            if (_profileCode)
            {
                _codeProfileTimers["CreateTable"].Stop();
            }
            if (_profileCode)
            {
                _codeProfileTimers["ProcessStart"].Stop();
            }
        }

        /// <summary>
        /// Handle process stop events
        /// </summary>
        /// <param name="data">Trace event data</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessStop(TraceEvent data)
        {
            if (_profileCode)
            {
                _codeProfileCounters["ProcessStop"] += 1;
                _codeProfileTimers["ProcessStop"].Start();
            }

            int pid = data.ProcessID;

            if (_verbosity >= 3)
            {
                _debugLog.WriteLine("Process Stop " + pid);
            }

            // Ignore the idle PID  because we never created an object for it 
            if (pid == IdlePid)
            {
                if (_profileCode)
                {
                    _codeProfileTimers["ProcessStop"].Stop();
                }
                return;
            }

            // We were receiving DCSTOP events with no corresponding starts
            if (!_activeProcesses.ContainsKey(pid))
            {
                _debugLog.WriteLine("Process missing from dict");
                if (_endService)
                {
                    _debugLog.WriteLine("Probably a DCSTOP, ignoring");
                    return;
                }
            }

            //Get process info 
            ProcessInfo stoppingProcess = _activeProcesses[pid];

            if (_verbosity >= 3)
            {
                _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + " " + "Process Stop: " +
                                    stoppingProcess.Name + " " + stoppingProcess.Pid);
            }

            // Set the stop time
            stoppingProcess.StopRelativeMSec = data.TimeStampRelativeMSec;

            // Update the process end time in the database
            _database.UpdateProcessEnd(stoppingProcess.StopRelativeMSec, stoppingProcess.Guid);

            // Flag for deletion
            stoppingProcess.DeletionFlag = data.TimeStampRelativeMSec;

            // Put it in the deletion queue
            _processesToDelete.Add(stoppingProcess);

            if (_profileCode)
            {
                _codeProfileTimers["ProcessStop"].Stop();
            }
        }


        /// <summary>
        /// Wrapper for regular thread starts
        /// </summary>
        /// <param name="data"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThreadStart(TraceEvent data)
        {
            ThreadStartHelper(data, false);
        }


        /// <summary>
        /// Wrapper for dc thread starts
        /// </summary>
        /// <param name="data"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThreadDcStart(TraceEvent data)
        {
            ThreadStartHelper(data, true);
        }


        /// <summary>
        /// Process thread starts
        /// </summary>
        /// <param name="data">Trace event data</param>
        /// <param name="dcStart">True if DC start</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThreadStartHelper(TraceEvent data, bool dcStart)
        {
            if (_profileCode)
            {
                _codeProfileCounters["ThreadStart"] += 1;
                _codeProfileTimers["ThreadStart"].Start();
            }

            ThreadTraceData threadData = (ThreadTraceData) data;
            int tid = data.ThreadID;

            if (_verbosity >= 4)
            {
                _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + "Thread start " + tid +
                                    " for pid " + data.ProcessID + " " + threadData.ProcessID);
            }

            // system idle process has as many threads as there are cores, all with diplicate Tid and Pid 0.  We ignore these.
            if (tid == 0 && data.ProcessID == 0)
            {
                if (_profileCode)
                {
                    _codeProfileTimers["ThreadStart"].Stop();
                }
                return;
            }

            if (_unkownThreads.ContainsKey(tid))
            {
                // This means it is a TID that we saw in a context switch already.  We need to update its info.  
                _unkownThreads[tid].Pid = data.ProcessID;
                _unkownThreads[tid].ProcessGuid = _activeProcesses[data.ProcessID].Guid;
                _unkownThreads[tid].PidStartRelativeMSec = _activeProcesses[data.ProcessID].StartRelativeMSec;

                // Put it in the correct process list
                _activeThreadsByProcess[data.ProcessID][tid] = _unkownThreads[tid];

                // Count new thread.
                _activeProcesses[data.ProcessID].TotalThreads += 1;

                // Remove from unknown list
                _unkownThreads.Remove(tid);

                if (_verbosity >= 4)
                {
                    _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                        data.TimeStampRelativeMSec + " " + "Updated PID in thread start" +
                                        _activeProcesses[data.ProcessID].Name + ", " +
                                        _activeThreadsByProcess[data.ProcessID][tid].Tid);
                }

                // Make sure the processor is updated if this thread is currently executing:
                for (int i = 0; i < _processorActiveProcesses.Count(); i++)
                {
                    if (_processorActiveThreads[i] == tid && _processorActiveProcesses[i] == UnknownPid)
                    {
                        if (_verbosity >= 4)
                        {
                            _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) +
                                                " " + data.TimeStampRelativeMSec + " Updated executing PID ");
                        }
                        _processorActiveProcesses[i] = data.ProcessID;
                    }
                }

                if (_profileCode)
                {
                    _codeProfileTimers["ThreadStart"].Stop();
                }
                return;
            }
            // Need to add duplicate TID mitigation code here!
            if (_activeThreadsByProcess.ContainsKey(data.ProcessID) &&
                _activeThreadsByProcess[data.ProcessID].ContainsKey(tid))
            {
                if (_verbosity >= 1)
                {
                    _debugLog.WriteLine("WARNING:  TID " + tid + " already exists for " + data.ProcessID);
                    _debugLog.WriteLine("Deleted:  " +
                                        _activeThreadsByProcess[data.ProcessID][tid].Deleted);
                    _debugLog.WriteLine("Deletion flag:  " +
                                        _activeThreadsByProcess[data.ProcessID][tid].DeletionFlag);
                }

                if (_activeThreadsByProcess[data.ProcessID][tid].DeletionFlag > 0)
                {
                    _activeThreadsByProcess[data.ProcessID][tid].DeletionFlag = data.TimeStampRelativeMSec -
                                                                                (_threadDeletionDelay*2);

                    ThreadDeletionQueue(data);

                    if (_activeThreadsByProcess[data.ProcessID].ContainsKey(tid))
                    {
                        _debugLog.WriteLine("ERROR:  TID " + tid + " already exists for " +
                                            data.ProcessID);
                        _debugLog.WriteLine("Deleted:  " +
                                            _activeThreadsByProcess[data.ProcessID][tid].Deleted);
                        _debugLog.WriteLine("Deletion flag:  " +
                                            _activeThreadsByProcess[data.ProcessID][tid].DeletionFlag);
                        throw new Exception("Duplicate thread disaster despite our correction efforts");
                    }
                }
            }
            //Create thread info object 
            ThreadInfo newThread = new ThreadInfo
            {
                Pid = data.ProcessID,
                Tid = tid,
                Start = data.TimeStamp,
                StartRelativeMSec = data.TimeStampRelativeMSec,
                PidStartRelativeMSec = _activeProcesses[data.ProcessID].StartRelativeMSec,
                Guid = Guid.NewGuid().ToString("N"),
                ProcessGuid = _activeProcesses[data.ProcessID].Guid
            };

            // Only create database entries and counter objects if we are doing thread tracing.
            if (_tracePerThread)
            {
                newThread.Counter =
                    new SystemCallTracer(Path.Combine(_tempPath, _dataDirectory, _dataSubFolder, newThread.Guid),
                        _debugLog);
                if (!dcStart && _tracePerThread)
                {
                    newThread.Counter.InitializeFullTrace(_maxTraceSyscalls, data.TimeStampRelativeMSec);
                }

                _database.AddThread(newThread);
            }

            // Count new thread.
            _activeProcesses[data.ProcessID].TotalThreads += 1;
            _activeThreadsByProcess[data.ProcessID][tid] = newThread;
            if (_profileCode)
            {
                _codeProfileTimers["ThreadStart"].Stop();
            }
        }

        /// <summary>
        /// Process thread stops
        /// </summary>
        /// <param name="data">Trace event data</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThreadStop(TraceEvent data)
        {
            if (_profileCode)
            {
                _codeProfileCounters["ThreadStop"] += 1;
                _codeProfileTimers["ThreadStop"].Start();
            }

            if (_verbosity >= 4)
            {
                _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + " " + "Thread Stop: " + data.ThreadID + " " +
                                    data.ProcessID);
            }

            // system idle process has as many threads as there are cores, all with duplicate Tid and Pid 0
            if (data.ProcessID == 0 && data.ThreadID == 0)
            {
                if (_profileCode)
                {
                    _codeProfileTimers["ThreadStop"].Stop();
                }
                return;
            }

            // Update Stop times for thread 
            _activeThreadsByProcess[data.ProcessID][data.ThreadID].StopRelativeMSec = data.TimeStampRelativeMSec;

            // Flag for deletion
            _activeThreadsByProcess[data.ProcessID][data.ThreadID].DeletionFlag = data.TimeStampRelativeMSec;

            // Only update database if we are doing thread analysis
            if (_tracePerThread)
            {
                _database.UpdateThreadEnd(data.TimeStampRelativeMSec,
                    _activeThreadsByProcess[data.ProcessID][data.ThreadID].Guid);
            }

            _threadsToDelete.Add(_activeThreadsByProcess[data.ProcessID][data.ThreadID]);
            if (_profileCode)
            {
                _codeProfileTimers["ThreadStop"].Stop();
            }
        }

        /// <summary>
        /// Processes context switches, which is a lot of work.  A lot of
        /// error checking here to be sure what we are tracking matches the
        /// the information reported by ETW.
        /// </summary>
        /// <param name="data">Trace event data</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ContextSwitch(TraceEvent data)
        {
            // Get the context switch data
            CSwitchTraceData cSwitchData = (CSwitchTraceData) data;

            if (_profileCode)
            {
                _codeProfileCounters["ContextSwitch"] += 1;
                _codeProfileTimers["ContextSwitch"].Start();
            }

            // Debug logging
            if (_verbosity >= 5)
            {
                _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + " Exchanged " + cSwitchData.OldThreadID +
                                    " " + cSwitchData.OldProcessID + " for " + cSwitchData.NewThreadID + " " +
                                    cSwitchData.NewProcessID + " ON CORE " + cSwitchData.ProcessorNumber);
            }


            // At the context switches we check to see whether we should do some writing and comitting.
            if (_lastCommit < -99)
            {
                _lastCommit = data.TimeStampRelativeMSec;
            }
            if (_lastCommit + _commitInterval <= data.TimeStampRelativeMSec)
            {
                //Database commits
                if (_profileCode)
                {
                    _codeProfileCounters["Commit"] += 1;
                    _codeProfileTimers["Commit"].Start();
                }
                _database.Commit();
                if (_profileCode)
                {
                    _codeProfileTimers["Commit"].Stop();
                }

                _lastCommit = data.TimeStampRelativeMSec;
            }


            // Update the last CSwitch time
            _lastCSwitch[cSwitchData.ProcessorNumber] = data.TimeStampRelativeMSec;

            // Should we do a deletion check?
            if (data.TimeStampRelativeMSec > _lastDeletionCheck + _minBackoff)
            {
                ThreadDeletionQueue(data);
                ProcessDeletionQueue(data);
                _lastDeletionCheck = data.TimeStampRelativeMSec;
            }

            // First handle what is being switched out -- As long as it is not the default.
            if (_processorActiveThreads[cSwitchData.ProcessorNumber] != DefaultProcessorValue)
            {
                // Verify that old thread IDs match
                if (_processorActiveThreads[cSwitchData.ProcessorNumber] != cSwitchData.OldThreadID)
                {
                    _debugLog.Write("CSWITCH error.  Old thread mismatch. Switched out " + cSwitchData.OldThreadID +
                                    " but should have been" + _processorActiveThreads[cSwitchData.ProcessorNumber]);
                    _debugLog.Flush();
                    throw new Exception("CSWITCH OldThread Mismatch");
                }

                // For any old non-idle process, we need to update the old thread and process information.
                if (cSwitchData.OldThreadID != IdlePid)
                {
                    // Easy Case:  We already know about old process and thread.
                    if (_activeThreadsByProcess.ContainsKey(cSwitchData.OldProcessID) &&
                        _activeThreadsByProcess[cSwitchData.OldProcessID].ContainsKey(cSwitchData.OldThreadID))
                    {
                        // Update thread activity 
                        _activeThreadsByProcess[cSwitchData.OldProcessID][cSwitchData.OldThreadID].IsActive = false;
                        _activeThreadsByProcess[cSwitchData.OldProcessID][cSwitchData.OldThreadID].LastActive =
                            cSwitchData.TimeStampRelativeMSec;

                        // Update process activity
                        _activeProcesses[cSwitchData.OldProcessID].ActiveThreads -= 1;
                        _activeProcesses[cSwitchData.OldProcessID].LastActive = cSwitchData.TimeStampRelativeMSec;
                    }

                    // Harder case:  We know about old thread, but not the process.
                    else if (_unkownThreads.ContainsKey(cSwitchData.OldThreadID))
                    {
                        _unkownThreads[cSwitchData.OldThreadID].IsActive = false;
                        _unkownThreads[cSwitchData.OldThreadID].LastActive = cSwitchData.TimeStampRelativeMSec;

                        // Update the process information if the old PID exists now.
                        if (cSwitchData.OldProcessID > 0)
                        {
                            _unkownThreads[cSwitchData.OldThreadID].Pid = cSwitchData.OldProcessID;

                            // Add thread to the process thread list
                            _activeThreadsByProcess[cSwitchData.OldProcessID][cSwitchData.OldThreadID] =
                                _unkownThreads[cSwitchData.OldThreadID];

                            // Update GUID
                            _unkownThreads[cSwitchData.OldThreadID].ProcessGuid =
                                _activeProcesses[cSwitchData.OldProcessID].Guid;

                            // New thread for this process
                            _activeProcesses[cSwitchData.OldProcessID].TotalThreads += 1;

                            //Remove from UnkownThreads
                            _unkownThreads.Remove(cSwitchData.OldThreadID);

                            // Log information
                            if (_verbosity >= 3)
                            {
                                _debugLog.WriteLine(
                                    (_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + "Updated PID to " +
                                    cSwitchData.OldProcessID + " for switched out thread " +
                                    cSwitchData.OldThreadID);
                            }

                            // Update Active processors for this thread 
                            for (int i = 0; i < _processorActiveProcesses.Count(); i++)
                            {
                                if (i != cSwitchData.ProcessorNumber &&
                                    _processorActiveThreads[i] == cSwitchData.OldThreadID &&
                                    _processorActiveProcesses[i] == UnknownPid)
                                {
                                    if (_verbosity >= 3)
                                    {
                                        _debugLog.WriteLine(
                                            (_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                            data.TimeStampRelativeMSec + " Updated executing PID ");
                                    }
                                    _processorActiveProcesses[i] = cSwitchData.OldProcessID;
                                    _activeProcesses[cSwitchData.OldProcessID].ActiveThreads += 1;
                                }
                            }
                        }
                    }

                    // Otherwise, we are in an error condition.
                    else
                    {
                        _debugLog.Write("FATAL CSWITCH ERROR:  Don't know anything about switched out thread.");
                        _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                            data.TimeStampRelativeMSec + " Exchanged " +
                                            cSwitchData.OldThreadID + " " + cSwitchData.OldProcessID + " for " +
                                            cSwitchData.NewThreadID + " " +
                                            cSwitchData.NewProcessID + " ON CORE " +
                                            cSwitchData.ProcessorNumber);
                        _debugLog.Flush();
                        throw new Exception("FATAL CSWITCH ERROR:  Don't know anything about switched out thread.");
                    }
                }
            }


            // Gratuitious logging for debugging purposes only.
            //DebugLog.WriteLine("Processes:" + String.Join(",", ProcessorActiveProcesses));
            //DebugLog.WriteLine("Threads:" + String.Join(",", ProcessorActiveThreads));
            // If the new thread is the system IDLE process, we are fine.  Just set it and continue 
            int newThreadId = cSwitchData.NewThreadID;
            int newProcessId = cSwitchData.NewProcessID;

            // For Nonzero new processes, we have work to do.
            if (cSwitchData.NewThreadID != IdlePid)
            {
                // If we know about both the thread and process already
                if (_activeThreadsByProcess.ContainsKey(cSwitchData.NewProcessID) &&
                    _activeThreadsByProcess[cSwitchData.NewProcessID].ContainsKey(cSwitchData.NewThreadID))
                {
                    // Update thread activity 
                    _activeThreadsByProcess[cSwitchData.NewProcessID][cSwitchData.NewThreadID].IsActive = true;

                    // Update process activity
                    _activeProcesses[cSwitchData.NewProcessID].ActiveThreads += 1;
                }
                // If we only know about the thread 
                else if (_unkownThreads.ContainsKey(cSwitchData.NewThreadID))
                {
                    _unkownThreads[cSwitchData.NewThreadID].IsActive = true;
                    newProcessId = UnknownPid;
                }

                // If we don't know about the thread yet and process is unknown, it is the weird case we see every now and then.
                else if (cSwitchData.NewProcessID < 0)
                {
                    if (_verbosity >= 4)
                    {
                        _debugLog.WriteLine("CSwitch:  Created new TID in thread list (" + cSwitchData.NewThreadID + ")");
                        _debugLog.WriteLine("Threads Old:  " + cSwitchData.OldThreadID + "  New:  " +
                                            cSwitchData.NewThreadID);
                        _debugLog.WriteLine("Processes Old:  " + cSwitchData.OldProcessID + "  New:  " +
                                            cSwitchData.NewProcessID);
                    }

                    //Create thread info object 
                    ThreadInfo newThread = new ThreadInfo
                    {
                        Tid = cSwitchData.NewThreadID,
                        Pid = UnknownPid,
                        Start = data.TimeStamp,
                        StartRelativeMSec = data.TimeStampRelativeMSec,
                        Guid = Guid.NewGuid().ToString("N")
                    };

                    // Create a new tracker
                    newThread.Counter =
                        new SystemCallTracer(Path.Combine(_tempPath, _dataDirectory, _dataSubFolder, newThread.Guid),
                            _debugLog);
                    if (_tracePerThread)
                    {
                        newThread.Counter.InitializeFullTrace(_maxTraceSyscalls, data.TimeStampRelativeMSec);
                    }

                    _unkownThreads[cSwitchData.NewThreadID] = newThread;
                    newProcessId = UnknownPid;
                }

                // Otherwise we are in an error condition
                else
                {
                    _debugLog.Write("FATAL CSWITCH ERROR:  Don't know anything about switched in thread.");
                    _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                        data.TimeStampRelativeMSec + " Exchanged " + cSwitchData.OldThreadID +
                                        " " + cSwitchData.OldProcessID + " for " + cSwitchData.NewThreadID +
                                        " " + cSwitchData.NewProcessID + " ON CORE " +
                                        cSwitchData.ProcessorNumber);
                    _debugLog.Flush();
                    throw new Exception("FATAL CSWITCH ERROR:  Don't know anything about switched in thread.");
                }
            }

            // Update information about the threads and processes on the cores
            _processorActiveProcesses[cSwitchData.ProcessorNumber] = newProcessId;
            _processorActiveThreads[cSwitchData.ProcessorNumber] = newThreadId;


            if (_profileCode)
            {
                _codeProfileTimers["ContextSwitch"].Stop();
            }
        }


        /// <summary>
        /// Processes the thread deletion queue 
        /// </summary>
        /// <param name="data">Trace event data</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThreadDeletionQueue(TraceEvent data)
        {
            if (_profileCode)
            {
                _codeProfileCounters["ThreadDeletionQueue"] += 1;
                _codeProfileTimers["ThreadDeletionQueue"].Start();
            }

            // Return if there is nothing to do.
            if (_threadsToDelete.Count != 0)
            {
                // Otherwise loop over all the threads to see which ones are ready to be deleted.
                for (int i = _threadsToDelete.Count - 1; i >= 0; i--)
                {
                    var thread = _threadsToDelete[i];

                    if (thread.IsActive)
                    {
                        _threadDeletionDelay *= 1.1;
                        if (_verbosity >= 4)
                        {
                            _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) +
                                                " " + data.TimeStampRelativeMSec +
                                                " Thread delay updated because still active. " + thread.Tid);
                        }
                    }

                    // If the deletion time has passed, see if it is ready
                    else if (data.TimeStampRelativeMSec > thread.DeletionFlag + _threadDeletionDelay)
                    {
                        // If there is no active process associated with this thread, good!
                        if (!_activeProcesses.ContainsKey(thread.Pid))
                        {
                            if (_verbosity >= 4)
                            {
                                _debugLog.WriteLine(
                                    (_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + " " +
                                    "Deleted thread with no active process" + thread.Tid + "," +
                                    thread.Pid);
                            }

                            // Remove from the unknown threads 
                            _unkownThreads.Remove(thread.Pid);

                            // Dispose of the commands -- Do I need to write a dispose method for the Counter?
                            if (thread.Counter != null)
                            {
                                thread.Counter.Close();
                            }
                            thread.Deleted = true;

                            // Remove thread from deletion list
                            _threadsToDelete.RemoveAt(i);
                        }

                        // Else we just remove the old thread from its process
                        else
                        {
                            if (_verbosity >= 4)
                            {
                                _debugLog.WriteLine(
                                    (_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) + " " +
                                    data.TimeStampRelativeMSec + " " + "Thread deleted normally." +
                                    thread.Tid + "," + thread.Pid);
                            }

                            _activeThreadsByProcess[thread.Pid].Remove(thread.Tid);

                            _activeProcesses[thread.Pid].TotalThreads -= 1;

                            // Dispose of the commands
                            if (thread.Counter != null)
                            {
                                thread.Counter.Close();
                            }

                            thread.Deleted = true;

                            _threadsToDelete.RemoveAt(i);
                        }
                    }
                }
            }
            if (_profileCode)
            {
                _codeProfileTimers["ThreadDeletionQueue"].Stop();
            }
        }

        /// <summary>
        /// Process the process deletion queue
        /// </summary>
        /// <param name="data">Trace event data</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessDeletionQueue(TraceEvent data)
        {
            if (_processesToDelete.Count != 0)
            {
                for (int i = _processesToDelete.Count - 1; i >= 0; i--)
                {
                    ProcessInfo process = _processesToDelete[i];

                    // Process is still active
                    if (process.ActiveThreads > 0)
                    {
                        process.DeletionFlag = data.TimeStampRelativeMSec;
                        if (_verbosity >= 5)
                        {
                            _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) +
                                                " " + data.TimeStampRelativeMSec + " " +
                                                "process still active.  Deletion delayed.  " + process.Pid);
                        }
                    }

                    // Process still has threads
                    else if (process.TotalThreads > 0)
                    {
                    }

                    // Process is ready to be removed when it has no threads and delay is over
                    else if (data.TimeStampRelativeMSec > process.DeletionFlag + _processDeletionDelay)
                    {
                        if (_verbosity >= 3)
                        {
                            _debugLog.WriteLine((_timer.ElapsedMilliseconds - data.TimeStampRelativeMSec) +
                                                " " + data.TimeStampRelativeMSec + " Removed old process " +
                                                process.Pid);
                        }

                        // Remove process
                        _activeProcesses.Remove(process.Pid);

                        // remove thread list for process
                        _activeThreadsByProcess.Remove(process.Pid);

                        // Dispose of the commands
                        if (process.Counter != null)
                        {
                            process.Counter.Close();
                        }

                        process.Deleted = true;

                        //Remove it from list
                        _processesToDelete.RemoveAt(i);
                    }
                }
            }
        }

        /// <summary>
        /// System call enter processing
        /// </summary>
        /// <param name="data">Trace event data</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SystemCallEnter(TraceEvent data)
        {
            if (_profileCode)
            {
                _codeProfileCounters["Syscall"] += 1;
                _codeProfileTimers["Syscall"].Start();
            }

            int index = -2;
            SysCallEnterTraceData traceData = (SysCallEnterTraceData) data;

            if (traceData.SysCallAddress >= _ntLowestAddress && traceData.SysCallAddress <= _ntMaxAddress)
            {
                index = _ntMap[(traceData.SysCallAddress - _ntLowestAddress)];

                // This is here for now for debugging puposes as a sanity check that we are tracing whole kernel
                if (index == -1)
                {
                    _debugLog.WriteLine("UNKNOWN System Call Enter NT {0:X} on core {1} ", traceData.SysCallAddress,
                        traceData.ProcessorNumber);
                }
            }

            if (index >= 0)
            {
                // Do host-wide data collection
                if (_traceHostLevel)
                {
                    _systemWideCounter.Add((ushort) index, data.TimeStampRelativeMSec);
                }

                // Do process level data collection
                if (_tracePerProcess)
                {
                    if (_activeProcesses.ContainsKey(_processorActiveProcesses[traceData.ProcessorNumber]))
                    {
                        ProcessInfo process = _activeProcesses[_processorActiveProcesses[traceData.ProcessorNumber]];
                        process.Counter.Add((ushort) index, data.TimeStampRelativeMSec);
                    }
                }


                // Do it per thread
                // Do process level data collection
                if (_tracePerThread)
                {
                    ThreadInfo thread = null;

                    if (_unkownThreads.ContainsKey(_processorActiveThreads[traceData.ProcessorNumber]))
                    {
                        thread = _unkownThreads[_processorActiveThreads[traceData.ProcessorNumber]];
                    }
                    else if (_activeThreadsByProcess.ContainsKey(_processorActiveProcesses[traceData.ProcessorNumber]) &&
                             _activeThreadsByProcess[_processorActiveProcesses[traceData.ProcessorNumber]].ContainsKey(
                                 _processorActiveThreads[traceData.ProcessorNumber]))
                    {
                        thread =
                            _activeThreadsByProcess[_processorActiveProcesses[traceData.ProcessorNumber]][
                                _processorActiveThreads[traceData.ProcessorNumber]];
                    }

                    if (thread != null)
                    {
                        thread.Counter.Add((ushort) index, data.TimeStampRelativeMSec);
                    }
                }
            }
            if (_profileCode)
            {
                _codeProfileTimers["Syscall"].Stop();
            }
        }

        /// <summary>
        /// Get the base addresses of the kernel
        /// </summary>
        /// <returns>true upon success</returns>
        private bool GetBaseAddresses()
        {
            uint bytesNeeded;

            // See how big the buffer needs to be 
            var success = EnumDeviceDrivers(null, 0, out bytesNeeded);
            _debugLog.WriteLine("EnumDeviceDrivers Finished");
            _debugLog.Flush();

            // Check error conditions
            if (!success)
            {
                return false;
            }
            if (bytesNeeded == 0)
            {
                return false;
            }

            // Allocate the array; as each ID is a 4-byte int, it should be 1/4th the size of bytesNeeded
            uint arraySizeBytes = bytesNeeded;
#if X86
            uint ArraySize = BytesNeeded / 4;
            UInt32[] Addresses = new UInt32[ArraySize];
#else
            uint arraySize = bytesNeeded/8;
            UInt64[] addresses = new UInt64[arraySize];
#endif

            // Now fill the array with device driver information
            success = EnumDeviceDrivers(addresses, arraySizeBytes, out bytesNeeded);
            _debugLog.WriteLine("Second EnumDeviceDrivers Finished");
            _debugLog.Flush();
            // Check error conditions
            if (!success)
            {
                return false;
            }

            // Iterate over all the device drivers until we find the kernel
            // Assume the base name is no more than 1000 characters
            StringBuilder driverName = new StringBuilder(1000);
            for (int i = 0; i < arraySize; i++)
            {
                GetDeviceDriverBaseName(addresses[i], driverName, driverName.Capacity);

                String driverNameString = driverName.ToString();

                // Kernel has different names on different windows versions
                String[] possibleNames = {"ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe"};

                foreach (String name in possibleNames)
                {
                    if (driverNameString == name)
                    {
                        _debugLog.WriteLine("Found " + name);
                        _debugLog.WriteLine(addresses[i]);
                        _debugLog.Flush();
                        _ntKernelAddress = addresses[i];
                        _ntKernelImageName = name;
                        break;
                    }
                }
            }
            _debugLog.WriteLine("StringBuilder Finished");
            _debugLog.Flush();
            return (_ntKernelAddress > 0);
        }

        /// <summary>
        /// Starts data collection
        /// </summary>
        public void Start()
        {
            _endService = false;

            // Setup Profiling firsst 
            if (_profileCode)
            {
                foreach (string str in _codeProfileKeys)
                {
                    _codeProfileTimers.Add(str, new Stopwatch());
                    _codeProfileCounters.Add(str, 0);
                }
            }

            // Reset Last SyscallEnter time and deletion check
            _lastDeletionCheck = -110000;
            _lastCommit = -1;

            // Create data directory (if it doesn't already exist). 
            Directory.CreateDirectory(Path.Combine(_tempPath, Properties.SystemCallServiceSettings.Default.DataDirectory));

            // Create a subdirectory to store the data 
            _dataSubFolder = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            Directory.CreateDirectory(Path.Combine(_tempPath, Properties.SystemCallServiceSettings.Default.DataDirectory,
                _dataSubFolder));

            // Create the logfile
            _debugLog =
                new StreamWriter(Path.Combine(_tempPath, Properties.SystemCallServiceSettings.Default.DataDirectory,
                    _dataSubFolder, Properties.SystemCallServiceSettings.Default.DebugLogFilename));
            
            // Dump some config information in the debug log
            foreach (string prop in _properties)
            {
                _debugLog.WriteLine(prop + " " + Properties.SystemCallServiceSettings.Default[prop]);
            }
            
            _debugLog.Flush();

            // Start the database interface
            _database =
                new DatabaseInterface(
                    Path.Combine(_tempPath, Properties.SystemCallServiceSettings.Default.DataDirectory, _dataSubFolder,
                        "database.sqlite"), _debugLog);

            _debugLog.WriteLine("Started Database Interface");
            _debugLog.Flush();

            // Get base kernel addresses -- must be done first to get correct image name because of x86 implementation
            if (!GetBaseAddresses())
            {
                _debugLog.WriteLine("Unable to fetch base addresses for the kernel.  Unable to continue.");
                _debugLog.Flush();
                throw new Exception("Unable to fetch base addresses for the kernel.  Unable to continue.");
            }

            _debugLog.WriteLine("Done GetBaseAddresses");
            _debugLog.Flush();

            // Get system information
            GetSystemInformation();
            _debugLog.WriteLine("Done adding SystemInformation");
            _debugLog.Flush();

            // Load address mappings
            _ntMap = LoadAddressMaps(_ntKernelImageName, _systemInfo.NtoskrnlVersion,
                Properties.SystemCallServiceSettings.Default.NtSensorList, out _syscallNameList, out _ntLowestAddress,
                out _ntMaxAddress, 0, _ntKernelAddress);
            _debugLog.WriteLine("Done LoadAddressMaps");
            _debugLog.Flush();


            if (_ntMap == null)
            {
                // TODO:  Exit cleanly?  This was put here for the case when automatic downloading was enabled.
                // We don't want to quit forever, but retry in whatever the specified interval is.
                Thread.Sleep((int) Properties.SystemCallServiceSettings.Default.AutoResetMs);
                return;
            }

            _debugLog.WriteLine(_syscallNameList.Count() + " nt sensors active");
            _debugLog.Flush();
            
            // Setup the data table creation and insertion queries and create one for the system-wide data
            _systemWideCounter =
                new SystemCallTracer(
                    Path.Combine(_tempPath, Properties.SystemCallServiceSettings.Default.DataDirectory, _dataSubFolder,
                        "host_data"), _debugLog);
            if (Properties.SystemCallServiceSettings.Default.TraceHostLevel)
            {
                _systemWideCounter.InitializeFullTrace(-1, 0);
            }

            // Start the timer
            _resetTimer.Interval = Properties.SystemCallServiceSettings.Default.AutoResetMs;
            _resetTimer.Start();

            // Clear all the data structures that are populated during a trace
            _tableCreations.Clear();
            _processesToDelete.Clear();
            _threadsToDelete.Clear();
            _activeThreadsByProcess.Clear();
            _unkownThreads.Clear();
            _activeProcesses.Clear();
            _timer.Restart();

            // Setup Thread and Process tracking, initialize to default values
            _processorActiveThreads = new int[_logicalProcessorCount];
            _processorActiveProcesses = new int[_logicalProcessorCount];

            for (int i = 0; i < _logicalProcessorCount; i++)
            {
                _processorActiveThreads[i] = DefaultProcessorValue;
                _processorActiveProcesses[i] = DefaultProcessorValue;
            }

            // Create the last cswitch time vector
            _lastCSwitch = new double[_logicalProcessorCount];
            for (int i = 0; i < _lastCSwitch.Count(); i++)
            {
                // Start it at a very negative value since timestamps usually start out negative
                _lastCSwitch[i] = -110000;
            }

            // Kernel addresses
            _debugLog.WriteLine("ntoskrnl.exe version:  " +
                                FileVersionInfo.GetVersionInfo(
                                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                        _ntKernelImageName)).ProductVersion);
            _debugLog.WriteLine("NT:    {0:X}", _ntKernelAddress);
            _debugLog.Flush();

            // The session name for the ETW trace has to be NT Kernel Logger for doing the kernel logging.
            // Relevant links:
            //   http://stackoverflow.com/questions/16068051/consuming-an-etw-kernel-trace-using-c-sharp
            //   http://blogs.msdn.com/b/vancem/archive/2013/03/09/using-traceevent-to-mine-information-in-os-registered-etw-providers.aspx

            // Opens up a real time session for the trace events.  Details about using statement  http://msdn.microsoft.com/en-us/library/yh598w02.aspx
            using (var eventTracingSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
                // the null second parameter means 'real time session'
            {
                // Save it as an instance variable
                _eventTracingSession = eventTracingSession;

                // Select those providers that we want data from:  PRocess, Thread, and Context switch.  
                eventTracingSession.EnableKernelProvider(KernelTraceEventParser.Keywords.ContextSwitch |
                                                            KernelTraceEventParser.Keywords.Process |
                                                            KernelTraceEventParser.Keywords.Thread |
                                                            KernelTraceEventParser.Keywords.SystemCall);
                // Need to figure out whether DPC or anything else belongs here.  

                // Setup the handlers
                eventTracingSession.Source.Kernel.PerfInfoSysClEnter += SystemCallEnter;
                eventTracingSession.Source.Kernel.ThreadCSwitch += ContextSwitch;


                eventTracingSession.Source.Kernel.ThreadStart += ThreadStart;
                eventTracingSession.Source.Kernel.ThreadDCStart += ThreadDcStart;
                eventTracingSession.Source.Kernel.ThreadStop += ThreadStop;
                eventTracingSession.Source.Kernel.ThreadDCStop += ThreadStop;

                eventTracingSession.Source.Kernel.ProcessStop += ProcessStop;
                eventTracingSession.Source.Kernel.ProcessDCStop += ProcessStop;


                eventTracingSession.Source.Kernel.ProcessStart += ProcessStart;
                eventTracingSession.Source.Kernel.ProcessDCStart += ProcessDcStart;

                // Start the timer
                _timer.Start();

                // Start Processing
                try
                {
                    eventTracingSession.Source.Process();
                }
                catch (Exception e)
                {
                    _debugLog.WriteLine("FATAL ERROR:  Exception in event processing.");
                    _debugLog.WriteLine(e.ToString());
                    _debugLog.WriteLine(e.StackTrace);
                    _eventLog.WriteEntry("Exception in event processing", EventLogEntryType.Error);
                    _eventLog.WriteEntry(e.ToString(), EventLogEntryType.Error);
                }

                _debugLog.Flush();

                // If processing has stopped, commit!
                _database.Commit();

                if (_profileCode)
                {
                    foreach (string str in _codeProfileKeys)
                    {
                        _debugLog.WriteLine(str + " " + _codeProfileCounters[str] + " calls " +
                                            _codeProfileTimers[str].ElapsedMilliseconds + " ms " +
                                            _codeProfileTimers[str].ElapsedMilliseconds/
                                            (float) _codeProfileCounters[str] + " ms per");
                    }
                }
                _eventLog.WriteEntry("Processing stopped", EventLogEntryType.Information);
                _debugLog.WriteLine("Lost events:  " + eventTracingSession.Source.EventsLost +
                                    "  Ideally, this number should be zero");
                _debugLog.Flush();
            }


            //Cleanup all the old data lying around.
            foreach (var process in _activeThreadsByProcess.Values)
            {
                foreach (var thread in process.Values)
                {
                    if (thread.Counter != null)
                    {
                        thread.Counter.Close();
                        thread.Counter = null;
                    }
                }
            }

            foreach (var process in _unkownThreads.Values)
            {
                if (process.Counter != null)
                {
                    process.Counter.Close();
                    process.Counter = null;
                }
            }

            foreach (var process in _processesToDelete)
            {
                if (process.Counter != null)
                {
                    process.Counter.Close();
                    process.Counter = null;
                }
            }

            foreach (var process in _threadsToDelete)
            {
                if (process.Counter != null)
                {
                    process.Counter.Close();
                    process.Counter = null;
                }
            }

            foreach (var process in _activeProcesses.Values)
            {
                if (process.Counter != null)
                {
                    process.Counter.Close();
                    process.Counter = null;
                }
            }

            _database.Commit();
            _database.CloseConnection();

            _debugLog.Flush();
            _debugLog.Close();
            _debugLog = null;

            _systemWideCounter.Close();

            SQLiteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        /// <summary>
        /// Stops the event tracing session
        /// </summary>
        /// <param name="endCollection">Indicates service should be stopped.</param>
        public void Stop(bool stopService)
        {
            _endService = stopService;
            _debugLog.WriteLine("SyscallCounter.Stop()");
            _eventTracingSession.Stop();
        }

        /// <summary>
        /// Timer for resetting the service
        /// </summary>
        /// <param name="source">Timer source</param>
        /// <param name="e">Time arguments</param>
        private void ResetTimerEvent(object source, ElapsedEventArgs e)
        {
            _debugLog.WriteLine("SyscallCounter.ResetTimerEvent()");
            Stop(false);
        }
    }
}