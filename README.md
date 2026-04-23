# Windows Evidence of Execution


## Table of Contents

1. [Overview](#overview)
2. [Windows Prefetch](#windows-prefetch)
   - [What Is Prefetch?](#what-is-prefetch)
   - [Forensic Value](#forensic-value)
   - [First and Last Execution Times](#first-and-last-execution-times)
   - [Auditing and Disabling Prefetch](#auditing-and-disabling-prefetch)
   - [Tool: PECmd.exe](#tool-pecmdexe)
3. [ShimCache (AppCompatCache)](#shimcache-appcompatcache)
   - [What Is ShimCache?](#what-is-shimcache)
   - [Registry Locations](#registry-locations)
   - [Per-OS Data Available](#per-os-data-available)
   - [Key Investigative Notes](#key-investigative-notes)
   - [Tool: AppCompatCacheParser](#tool-appcompatcacheparser)
4. [Amcache.hve](#amcachehve)
   - [What Is Amcache?](#what-is-amcache)
   - [What Amcache Tracks](#what-amcache-tracks)
   - [Three Categories of Entries](#three-categories-of-entries)
   - [Key Registry Keys Inside Amcache](#key-registry-keys-inside-amcache)
   - [Auditing Installed Drivers](#auditing-installed-drivers)
   - [Tool: AmcacheParser](#tool-amcacheparser)
5. [Automating Execution Analysis at Scale](#automating-execution-analysis-at-scale)
   - [What to Search For](#what-to-search-for)
   - [Tool: appcompatprocessor.py](#tool-appcompatprocessorpy)
   - [appcompatprocessor.py Modules](#appcompatprocessorpy-modules)
   - [Stacking with appcompatprocessor.py](#stacking-with-appcompatprocessorpy)
6. [Artifact Comparison Summary](#artifact-comparison-summary)
7. [Key Takeaways](#key-takeaways)

---

## Overview

When investigating a compromised Windows system, one of the most critical questions is: **what programs have been executed?**  

Windows maintains several artifacts — some by design for performance, others for compatibility — that collectively provide a powerful picture of execution history. This guide covers three primary artifacts:

| Artifact | Primary Value | Location |
|---|---|---|
| **Prefetch** | Execution time(s), run count, files touched | `C:\Windows\Prefetch\` |
| **ShimCache** | Execution history, file path, last modified time | Registry `SYSTEM` hive |
| **Amcache.hve** | Executable presence, SHA1 hashes, driver info | `C:\Windows\AppCompat\Programs\Amcache.hve` |

Used together and cross-referenced, these artifacts can reconstruct attacker activity even after tools have been deleted.

---

## Windows Prefetch

### What Is Prefetch?

**Prefetching** is a Windows performance feature that pre-loads code pages from disk into memory before they are needed, speeding up application launch times. The **Cache Manager** monitors all files and directories referenced by an application during its first 10 seconds of execution, then records this information into a `.pf` file stored in `C:\Windows\Prefetch\`.

>  **Prefetch is available on Windows Workstation editions only** — it is **not** enabled by default on Windows Server editions.

**File naming format:**

```
<Executable Name>-<Hash>.pf
Example: CHROME.EXE-46AA1511.pf
```

The hash at the end is calculated based on the **directory path** from which the executable was launched. For certain "hosting" executables (like `svchost.exe`, `rundll32.exe`, `dllhost.exe`, `backgroundtaskhost.exe`), the hash also incorporates **command line arguments** — so multiple `.pf` files for these executables is normal behavior.

**Prefetch file limits by OS version:**

| Windows Version | Max Prefetch Files |
|---|---|
| Windows 7 and earlier | 128 |
| Windows 8 and later | 1,024 |

>  **Windows 10 and 11:** Prefetch files are now **compressed**. Tools must run on at least Windows 8 to decompress and parse them correctly.

---

### Forensic Value

Each prefetch file contains:

- **Executable name** — the name of the program that was run
- **Full path of execution** — the actual location the binary was launched from (embedded in the file references list, so hash calculation is rarely needed)
- **Run count** — the total number of times the application has been executed
- **Last execution time(s)** — up to **eight** embedded execution timestamps on Windows 8 and later
- **Files and directories referenced** — every file the application touched within the first 10 seconds of execution, including full path and disk volume

>  **Pro Tip:** The files-referenced list can be extraordinarily revealing. It may expose malicious DLLs loaded by a program, documents opened by Office applications, or files wiped by a cleanup tool.

**Multiple `.pf` files with the same executable name** is a significant indicator. For non-hosting executables, this means two copies of the same binary were executed **from different locations** — a strong sign of suspicious activity. For example, seeing two prefetch files for `cmd.exe` could mean a renamed or dropped `cmd.exe` was executed from outside `System32`.

>  **Important Caveat:** A `.pf` file being created does **not** guarantee the program successfully executed. Applications that fail on launch may still generate a prefetch file. Always cross-reference with other execution artifacts.

>  **Live Response Warning:** Running live response tools on a target system **creates new prefetch files** for those tools. Since the prefetch folder has a fixed file limit, the **oldest prefetch files may be deleted** to make room. **Always collect the Prefetch directory as an early priority** to avoid losing evidence.

---

### First and Last Execution Times

Prefetch provides two layers of timestamp information:

#### From File System Timestamps (of the `.pf` file itself):

| Timestamp | Meaning |
|---|---|
| **Creation time** of `.pf` file | First time the executable was ever run (~minus 10 seconds) |
| **Last modification time** of `.pf` file | Most recent execution (~minus 10 seconds) |

>  File system timestamps for prefetch files are written approximately **10 seconds after** execution. This is because the Cache Manager watches the application for 10 seconds before writing the `.pf` file. Subtract ~10 seconds when interpreting these times.

#### From Embedded Timestamps (inside the `.pf` file):

- **Windows 7:** One embedded last execution time
- **Windows 8 and later:** Up to **eight** embedded execution timestamps

>  When combined with the `.pf` file creation timestamp, Windows 8+ systems can yield up to **nine** execution times per application.

**A note on "first time of execution":**  
The creation time of the `.pf` file reflects only the first execution **we know about**. If the original `.pf` file aged out of the 128/1024 limit and was deleted, a new `.pf` would have been created on the next execution — resetting the creation timestamp. Use other execution artifacts (ShimCache, Amcache) to cross-reference and find the earliest known execution.

---

### Auditing and Disabling Prefetch

**Registry Location:**

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
```

**Value Name:** `EnablePrefetcher` (Type: `REG_DWORD`)

| Value | Behavior |
|---|---|
| `0` | Disabled |
| `1` | Application launch prefetching enabled |
| `2` | Boot prefetching enabled |
| `3` | Both application launch and boot prefetching enabled |

>  Prefetching has been observed **disabled on Windows 7 machines with SSDs**. This does not appear to be the case for newer Windows versions.

---

### Tool: PECmd.exe

**PECmd** (Prefetch Explorer Command Line) is written and maintained by SANS Instructor **Eric Zimmerman**. It parses prefetch file internal metadata and outputs results to CSV, JSON, or HTML.

**GitHub:** [EricZimmerman/PECmd](https://github.com/EricZimmerman/PECmd)

#### Common Usage

```cmd
# Parse entire Prefetch directory, export to CSV
PECmd.exe -d "E:\[root]\Windows\Prefetch" --csv "G:\cases" -q

# Parse a single .pf file
PECmd.exe -f "SDELETE.EXE-2288BD2E.PF"

# Parse with keyword highlighting
PECmd.exe -d "C:\Temp" -k "system32, fonts"

# Parse directory to CSV and JSON
PECmd.exe -d "C:\Temp" --csv "c:\temp" --json "c:\temp\json"

# Save CSV with custom filename
PECmd.exe -d "C:\Temp" --csv "c:\temp" --csvf foo.csv
```

#### Key Switches

| Switch | Description |
|---|---|
| `-d <dir>` | Directory to recursively process |
| `-f <file>` | Single `.pf` file to process |
| `-k <keywords>` | Comma-separated keywords to highlight (defaults include `temp`, `tmp`) |
| `-q` | Quiet output — use with `--csv` for clean exports |
| `--csv <dir>` | Directory to save CSV output |
| `--csvf <name>` | Custom CSV filename |
| `--json <dir>` | Directory to save JSON output |
| `--pretty` | Human-readable JSON layout |
| `--html <dir>` | Directory to save HTML output |
| `--dt` | Custom date/time format for timestamps |
| `--mp` | Higher precision timestamps (default: false) |

#### Output Explained

When parsing a **single file**, PECmd displays:
- Source file system timestamps (creation/modification) of the `.pf` file
- Executable name and prefetch hash
- Prefetch file format version
- Run count
- Embedded last run timestamp(s)
- Volume information
- Full list of files and directories referenced within first 10 seconds of execution

When parsing an **entire directory**, PECmd produces **two output files**:
1. **Detailed file** — run count, last run times, and files referenced for every `.pf` file
2. **Timeline file** — one row per embedded timestamp, making it easy to identify programs that executed near each other

---

## ShimCache (AppCompatCache)

### What Is ShimCache?

Microsoft's **Application Compatibility Cache** (commonly called **ShimCache**) was designed to detect and remediate program compatibility challenges at launch. When a program built for an older version of Windows is executed, the compatibility subsystem may apply "shims" — compatibility properties that allow it to behave as if it were running on an older OS.

**Critically for forensics:** Every executable that is checked for compatibility is **added to the AppCompatCache regardless of whether it needed shimming**. This means the cache effectively acts as a broad execution (and file presence) tracker.

>  One of the most powerful uses: If an attacker deletes their tools **and** the corresponding prefetch files, ShimCache entries may be the **only remaining evidence** that those executables existed on the system.

---

### Registry Locations

| OS Version | Registry Path |
|---|---|
| **Windows XP** | `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatibility\AppCompatCache` |
| **Windows Server 2003+ / Windows 7–11** | `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache` |

>  Multiple `ControlSet` entries may exist in the SYSTEM hive (e.g., `ControlSet001`, `ControlSet002`). On a running system, use `SYSTEM\CurrentControlSet`. On an offline system, determine the active ControlSet by reading the `Current` value at `SYSTEM\Select`.

**Entry limits by OS:**

| OS | Max Entries |
|---|---|
| Windows XP | 96 |
| Windows Server 2003 | 512 |
| Windows 7–11 / Server 2008–2022 | 1,024 |

---

### Per-OS Data Available

| Data Field | XP | Win7 | Win8/8.1 | Win10/11 |
|---|---|---|---|---|
| OS file path | ✅ | ✅ | ✅ | ✅ |
| Last modified date | ✅ | ✅ | ✅ | ✅ |
| File size | ✅ | | | |
| Last execution time | ✅ | | | |
| Execution flag (InsertFlag) | | ✅ | ✅ | ❌ Removed |

---

### Key Investigative Notes

**1. Entries are ordered most-recent first**  
The most recent shimmed entries appear at the top of the output — important since most versions do not store explicit execution timestamps.

**2. Data is only written on shutdown (or reboot on Win10+)**  
AppCompatCache entries are held in memory and **only committed to the registry on system shutdown or reboot**. Applications executed since the last shutdown will **not** appear in the SYSTEM hive until the next shutdown. This is a critical limitation — a running system's registry will be missing the most recent execution data.

**3. The InsertFlag — proving execution**  
Starting with **Windows Vista**, the `InsertFlag` value was introduced:
- `InsertFlag = True` → The application **was executed**
- `InsertFlag = False` → The application was **not** confirmed to have executed (may have been recorded preemptively by the OS when browsing a folder containing executables via File Explorer)

>  **Windows 10+:** The InsertFlag was **removed** from the data structure, even though preemptive additions to the cache continue. Exercise caution — presence in ShimCache on Win10+ **cannot** alone confirm execution.

**4. Renamed and modified files create new entries**  
If an application is **renamed, modified, or rewritten to disk** (e.g., `psexec.exe` reinstalling its service binary), a new ShimCache entry is created. This is extremely useful for detecting renamed tools — compare the `LastModified` timestamp stored in ShimCache against the file's actual last modified time. A mismatch indicates **timestamp manipulation (timestomping)**.

**5. Detecting timestomping**  
If `LastModified` in ShimCache ≠ actual file's `LastModified` on disk → the file's timestamp was likely manipulated after it was recorded in the cache.

---

### Tool: AppCompatCacheParser

**AppCompatCacheParser** is written and maintained by SANS Instructor **Eric Zimmerman**.

**GitHub:** [EricZimmerman/AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)

It parses offline SYSTEM hives or runs against a live system's registry. Supports Windows 7 and above. By default, it processes **all ControlSets** in the hive to ensure no historical data is missed.

#### Usage

```cmd
# Parse offline SYSTEM hive, export to CSV (sorted by timestamp descending)
AppCompatCacheParser.exe -f "E:\SYSTEM" --csv "G:\cases" -t

# Parse live (running) system
AppCompatCacheParser.exe --csv "G:\cases"

# Parse specific ControlSet only
AppCompatCacheParser.exe -f "E:\SYSTEM" -c 1 --csv "G:\cases"
```

#### Key Switches

| Switch | Description |
|---|---|
| `-f <path>` | Full path to SYSTEM hive. If omitted, uses live registry |
| `-c <n>` | Parse a specific ControlSet. Default: all ControlSets |
| `-t` | Sort last modified timestamps in descending order |
| `--csv <dir>` | Directory to save CSV results (required) |
| `--dt` | Custom date/time format |
| `-d` | Debug mode |

>  **Alternative tool:** Mandiant's **ShimCacheParser.py** operates on exported `.reg` files (via `reg.exe` export), making it a lightweight option for collecting ShimCache at scale across many systems without needing to copy full registry hives.

---

## Amcache.hve

### What Is Amcache?

**Amcache.hve** is a registry hive file introduced in Windows 8, and later backported to patched Windows 7 systems. It replaces the older `RecentFileCache.bcf` artifact. It is stored as a standalone registry hive at:

```
C:\Windows\AppCompat\Programs\Amcache.hve
```

Amcache is one of the most **information-rich** execution-related artifacts in Windows forensics. Its format is driven by **DLL version, not OS version** — meaning the data structure you encounter depends primarily on the system's **patch level**, not which version of Windows is installed. Always verify what version of the database you are analyzing.

>  Microsoft has changed the Amcache database format significantly at least **four times**. Data structures may vary widely between systems at different patch levels.

---

### What Amcache Tracks

For each executable and driver, Amcache can provide:

| Field | Description |
|---|---|
| **Full path** | Complete file path of the executable or driver |
| **File size** | Size of the binary |
| **File version** | Version number from PE header |
| **File description** | Metadata from the PE header |
| **Publisher** | Software publisher metadata |
| **Last modified date** | File system last modified time |
| **Compilation time** | PE header compile timestamp (valuable for malware IOC matching) |
| **Language ID** | Locale information |
| **SHA-1 hash** | Cryptographic hash of the executable or driver ← **most powerful field** |

>  The **SHA-1 hash** is exceptionally rare among Windows forensic artifacts. It enables direct comparison against:
> - **Known-good** databases (e.g., NSRL) to quickly identify legitimate files
> - **Known-bad** databases (e.g., VirusTotal) to identify renamed malware — even if the attacker renamed `mimikatz.exe` to something innocent-looking, the hash will still match

---

### Three Categories of Entries

It is critical to understand that **presence in Amcache does NOT always indicate execution**. Research by Blanche Lagny identified three distinct categories of files tracked:

| Category | Execution Confirmed? | Description |
|---|---|---|
| **1. Executed GUI apps** | ✅ Yes | Applications that ran and were shimmed for compatibility |
| **2. Execution-associated files** | ❌ No | Executables and drivers copied as part of another app's execution |
| **3. Compatibility Appraiser scan** | ❌ No | Executables present in scanned directories (`Program Files`, `Desktop`) — discovered by a scheduled task, not executed |

>  Only **Category 1** relates to actual execution, and it applies only to GUI applications that needed shimming — a small subset. **Use Amcache primarily to prove executable presence and gather metadata. Use Prefetch to prove execution and execution times.**

>  **Note on timestamps:** In the current version of Amcache, the last write time of registry keys primarily reflects when the **Microsoft Compatibility Appraiser scheduled task** updated the database — not when the file was executed. Do not interpret these timestamps as execution times.

---

### Key Registry Keys Inside Amcache

#### `InventoryApplicationFile`
The primary starting point. Contains one subkey per tracked executable. Key values include:

| Value Name | Description |
|---|---|
| `FileID` | SHA-1 hash (drop the leading four zeroes) |
| `LowerCaseLongPath` | Full file path |
| `Size` | File size |
| `LinkDate` | PE header compilation timestamp |

>  Multiple subkeys with the same executable name but different paths indicate the same binary was present in multiple locations — useful for detecting staging or copying activity.

#### `InventoryApplication`
Tracks **installed applications** — a subset of `InventoryApplicationFile`. Matched to file entries via the `ProgramId` value. Contains:
- Installation date (day-level granularity)
- Detailed publisher information

#### `InventoryDriverBinary`
Tracks **loaded drivers**. Crucial for investigations involving rootkits, bootkits, and security evasion. Per-driver information includes:
- Full path
- SHA-1 hash
- Whether the driver is signed (on 64-bit systems, **all legitimate drivers must be signed**)
- PE header metadata

>  On 64-bit systems, **unsigned drivers are an immediate red flag**. Look for drivers in non-standard folders with missing metadata as potential rootkit indicators.

---

### Auditing Installed Drivers

When reviewing `InventoryDriverBinary` entries, flag any driver that exhibits:

- **Non-standard path** (not in `System32\drivers` or a known vendor folder)
- **Missing PE metadata** (no description, publisher, or version)
- **Unsigned** on a 64-bit system
- **SHA-1 hash matching known malicious drivers** on VirusTotal or similar

>  Cross-reference suspicious driver hashes with VirusTotal. Even a driver that appears harmless at first glance may be a known forensic/security tool (like F-Response) or a kernel-level implant.

---

### Tool: AmcacheParser

**AmcacheParser** is written and maintained by SANS Instructor **Eric Zimmerman**.

**GitHub / Download:** [ericzimmerman.github.io](https://ericzimmerman.github.io/)

#### Usage

```cmd
# Parse Amcache hive, include all program-associated file information, export CSV
AmcacheParser.exe -f Amcache.hve -i --csv G:\cases
```

#### Key Switches

| Switch | Description |
|---|---|
| `-f <path>` | Full path to `Amcache.hve` |
| `-i` | Include file entries associated with Program entries (excluded by default) |
| `--csv <dir>` | Directory to save CSV output |
| `--allow <hash list>` | Allowlist filtering by SHA-1 |
| `--deny <hash list>` | Blocklist filtering by SHA-1 |

#### Output Files

AmcacheParser produces multiple CSV output files:

| Output File | Source Key | Contents |
|---|---|---|
| `Amcache_ProgramEntries.csv` | `InventoryApplication` | Installed applications, install dates, publisher info |
| `Amcache_AssociatedFileEntries.csv` | `InventoryApplicationFile` | Files associated with installed programs |
| `Amcache_UnassociatedFileEntries.csv` | `InventoryApplicationFile` | **Executables NOT part of any known installation** |
| `Amcache_DriverBinaries.csv` | `InventoryDriverBinary` | All drivers tracked by Amcache |

>  **`UnassociatedFileEntries` is your highest-priority output.** These are executables on the system that were not installed through any known package — standalone binaries dropped by an attacker (credential dumpers, network scanners, wiping tools, staging scripts). Start here.

---

## Automating Execution Analysis at Scale

### What to Search For

Application execution artifacts are ideal candidates for **enterprise-wide hunting** because the databases are small, easy to collect, and straightforward to normalize. When hunting at scale across many systems, look for:

**High-Signal Patterns:**

| Pattern | Significance |
|---|---|
| One or two-letter executable names | Common naming pattern for attacker tools |
| Execution from `$Recycle.Bin` | Strongly suspicious staging location |
| Execution from `System Volume Information` | Abnormal execution source |
| Execution from `Temp` or `%AppData%` | Common malware staging area |
| Known attacker tool names | `psexesvc.exe`, `wmic.exe`, `mimikatz.exe`, `pwdump.exe`, `rar.exe`, `sdelete.exe`, `certutil.exe` |
| Built-in recon tools appearing in unusual contexts | `whoami.exe`, `net.exe`, `ipconfig.exe`, `systeminfo.exe` |
| Execution from network shares | Lateral movement indicator |

>  Once specific attacker file names, paths, or hashes are known, they become **Indicators of Compromise (IOCs)** that can be searched across the entire environment to rapidly identify other affected systems.

---

### Tool: appcompatprocessor.py

**appcompatprocessor.py** is a Python and SQLite-based tool designed specifically for **enterprise-scale hunting** of ShimCache and Amcache data. Created by **Matias Bevilacqua**.

**GitHub:** [mbevilacqua/appcompatprocessor](https://github.com/mbevilacqua/appcompatprocessor)

It ingests ShimCache and Amcache data from many systems, normalizes it into a SQLite database, and provides powerful analytical modules for finding anomalies.

**Supported Input Formats:**
- Raw SYSTEM registry hive files
- Raw `Amcache.hve` registry hive files
- Output from Mandiant's `ShimCacheParser.py`
- In-memory ShimCache extraction output
- ZIP archives (saves an extra step when moving datasets)

---

### appcompatprocessor.py Modules

| Module | Description |
|---|---|
| `search` | Regex search against the database. Ships with **100+ pre-built regular expressions** for known-bad patterns. Easily extended via a text file (`AppCompatSearch.txt`) |
| `fsearch` | Search by a single field: `FileName`, `FilePath`, `Size`, `LastModified`, `ExecFlag`, etc. |
| `filehitcount` | Simple frequency stack — how many times each executable appears across all ingested systems |
| `tcorr` | **Temporal correlation** — finds files that regularly execute before or after each other. Identifies patterns and associated files that may not be obvious individually |
| `reconscan` | Searches for clusters of **common reconnaissance tools** executed near each other on the same host. Generates a probability score per system for how likely it experienced attacker recon activity |
| `leven` | **Levenshtein distance** search — finds filenames that are slight variations of known good names (e.g., `svchos.exe`, `lssass.exe`, `cssrs.exe`). Identifies "hiding in plain sight" techniques |
| `stack` | Full **least frequency of occurrence** analysis on any database field |
| `rndsearch` | Attempts to identify **randomly named files** — a common characteristic of malware-generated filenames |

---

### Stacking with appcompatprocessor.py

**Least Frequency of Occurrence (stacking)** is one of the most powerful techniques for finding anomalies across large datasets. The core principle: **malicious activity tends to appear on fewer systems than legitimate activity.**

**Example workflow:**

```
1. Stack all entries on "FilePath" filtered to entries containing "svchost.exe"

Results:
  C:\Windows\System32\svchost.exe     →  found on 847 systems  (expected)
  C:\Windows\SysWOW64\svchost.exe     →  found on 212 systems  (expected .NET hosting)
  C:\ProgramData\svchost.exe          →  found on   1 system   ← INVESTIGATE

2. Run fsearch for "ProgramData" in FilePath on the outlier system (DESKTOP-33)

Results:
  C:\ProgramData\svchost.exe          →  DESKTOP-33
  C:\ProgramData\svc.bat              →  DESKTOP-33  ← likely related
```

A single outlier found through stacking often leads to additional related findings on the same system — expanding the picture of the attack with each pivot.

**Example output from a `search` run using built-in signatures:**

```
[Root of RarSFX .exe]  BASE-WKSTN-01  C:\Users\spsql\AppData\Local\Temp\RarSFX0\setup.exe
[7zip]                 BASE-RD-02     C:\ProgramData\staging\7za.exe
[Startup persistence]  BASE-RD-05     C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\bginfo.bat
[Exec from VFS]        BASE-RD-04     \\172.16.6.16\c$\Windows\Temp\BrowsingHistoryView.exe
[Exec from VFS]        BASE-RD-04     \\172.16.6.16\c$\Windows\Temp\1.bat
```

Each line represents a hit from a built-in signature — execution from a network share, staging in ProgramData, self-extracting archives, and startup persistence are all immediately surfaced.

---

## Artifact Comparison Summary

| Property | Prefetch | ShimCache | Amcache |
|---|---|---|---|
| **Confirms execution?** | ✅ Yes (with caveats) | ⚠️ Win7/8 only (InsertFlag) | ⚠️ Category 1 only |
| **Execution timestamps** | ✅ Up to 9 times (Win8+) | ❌ XP only | ❌ |
| **Run count** | ✅ Yes | ❌ | ❌ |
| **Full file path** | ✅ Yes | ✅ Yes | ✅ Yes |
| **SHA-1 hash** | ❌ | ❌ | ✅ Yes |
| **Files referenced by app** | ✅ Yes | ❌ | ❌ |
| **Tracks renamed files** | ❌ | ✅ Yes (new entry) | ✅ Yes |
| **Detects timestomping** | ❌ | ✅ Comparison possible | ✅ Comparison possible |
| **Tracks drivers** | ❌ | ❌ | ✅ Yes |
| **Persists after tool deletion** | ⚠️ Until aged out | ✅ Until shutdown overwrites | ✅ Until Appraiser task rewrites |
| **Available on Server OS** | ❌ Not by default | ✅ Yes | ✅ Yes |
| **Written to disk when** | ~10s after execution | On shutdown / reboot | On Appraiser task run |

---

## Key Takeaways

- **Use all three artifacts together.** No single artifact tells the full story. Prefetch provides timestamps and run counts; ShimCache provides breadth across all executables including those whose prefetch files were deleted; Amcache provides SHA-1 hashes and driver visibility.

- **Prefetch is the gold standard for execution times** on workstation systems, providing up to nine timestamps per application on Windows 8 and later.

- **ShimCache survives tool deletion.** If an attacker deletes their tools and removes prefetch files, ShimCache may be the last remaining evidence that the executables existed.

- **Amcache's SHA-1 hash is uniquely powerful** — it can identify renamed malware that would otherwise hide behind an innocent filename.

- **Presence ≠ Execution in ShimCache (Win10+) and Amcache.** Always cross-reference with Prefetch or other behavioral evidence before concluding a file was run.

- **The `UnassociatedFileEntries` output from AmcacheParser is your first stop** when looking for attacker tools — these are executables with no known installation source.

- **Stacking across the enterprise reveals outliers** that are invisible when examining a single system. One suspicious executable on one machine out of 1,000 stands out immediately through frequency analysis.

- **Collect Prefetch early.** Running live response tools creates new `.pf` files and can push older ones out of the 1,024-file limit. Prioritize Prefetch collection before any other live execution.

