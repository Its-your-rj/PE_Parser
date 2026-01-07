# PE File Parser

A simple C program that reads and analyzes Windows executable files (like .exe and .dll files). This tool helps you understand what's inside these files without actually running them.

## What Does This Tool Do?

Imagine you have a Windows program file and you want to know what's inside it - what functions it uses, what libraries it needs, how it's organized - but you don't want to actually run it (especially if you think it might be malicious). This tool lets you peek inside and see all that information.

Think of it like being able to read the table of contents and index of a book without opening it. You can see the chapter names, how long each chapter is, and what topics are covered.

## Why Would You Need This?

There are several real-world situations where this is useful:

**If you're learning about security**: When you're studying how malware works, you need to examine suspicious files safely. This tool lets you see what the file does without the risk of running it.

**If you're troubleshooting programs**: Sometimes a program won't run because it's missing a DLL file. This tool shows you exactly which DLL files and functions a program needs.

**If you're curious about how programs work**: Want to understand how Windows loads and runs programs? This tool shows you all the internal structure.

**If you're doing forensics**: After a security incident, you might need to analyze files to understand what happened. This tool helps you examine files safely.

## What is a PE File Anyway?

PE stands for "Portable Executable". It's just Microsoft's fancy name for the file format used by all Windows programs. Every .exe file, every .dll library, and every .sys driver uses this format.

A PE file is organized like this:

- **Headers**: Think of these as the file's instructions to Windows. They say "I'm a 64-bit program" or "I need 5 megabytes of memory" or "Start running my code at this location".

- **Sections**: These are like chapters in a book. There's usually a section for the actual program code, a section for data, and a section for resources like icons and text.

- **Import Table**: This is a list of all the external functions the program uses. For example, if a program opens files, it needs functions from Windows like "CreateFile" and "ReadFile".

## The Address Translation Problem (And How We Solve It)

This is one of the trickier parts of reading PE files, but I'll explain it simply.

When a PE file sits on your hard drive, everything is at a specific location in the file - like page numbers in a book. But when Windows loads the program into memory to run it, it rearranges things for efficiency. So the addresses in the file don't match the addresses in memory.

The headers use "memory addresses" (where things will be when the program runs) but we're reading the file from disk (where things are right now). We need to translate between them.

Our program has a function called RvaToOffset that does this translation. It looks at the section headers (which act like a map) and figures out where to find things in the actual file.

You don't need to worry about the details - just know that the program handles this automatically so you get the right information.

## How to Compile and Run This Program

You need two things: Windows and a C compiler.

### If you have Visual Studio:

1. Open Visual Studio
2. Create a new "Empty Project"
3. Add the pe_parser.c file to your project
4. Press Ctrl+Shift+B to build it
5. You'll get a pe_parser.exe file

### If you have MinGW or GCC installed:

1. Open Command Prompt
2. Navigate to the folder with pe_parser.c
3. Type: `gcc pe_parser.c -o pe_parser.exe`
4. Press Enter

### If you have Microsoft's compiler (MSVC):

1. Open the Visual Studio Command Prompt
2. Type: `cl pe_parser.c`
3. Press Enter

## How to Use It

Once you've compiled it, using the program is simple. Open Command Prompt and type:

```
pe_parser.exe C:\path\to\some\file.exe
```

For example, to analyze Windows Notepad:

```
pe_parser.exe C:\Windows\System32\notepad.exe
```

You can analyze any .exe, .dll, or .sys file.

## Input: What Files Can You Analyze?

This tool accepts any Windows PE file as input. Here's what you can analyze:

### Executable Files (.exe)
These are your regular Windows programs. Examples:
- `notepad.exe` - Windows Notepad
- `chrome.exe` - Google Chrome browser
- `malware_sample.exe` - Suspicious file you want to examine

### Dynamic Link Libraries (.dll)
These are libraries that programs use to share code. Examples:
- `kernel32.dll` - Core Windows functions
- `user32.dll` - Windows UI functions
- `suspicious.dll` - Unknown library found on your system

### System Drivers (.sys)
These are low-level drivers. Examples:
- `ntfs.sys` - Windows file system driver
- `tcp.sys` - Network driver
- Any driver you want to examine

### How to Specify the Input

Simply provide the full path to the file:

```
pe_parser.exe C:\Windows\System32\notepad.exe
```

Or if the file is in the same folder as the program:

```
pe_parser.exe myprogram.exe
```

The program will read the entire file into memory and then parse its structure. It never executes the file, so it's safe to analyze potentially malicious files (though you should still use a virtual machine for unknown files).

## Understanding the Output: A Complete Breakdown

The program prints information in several sections. Let's go through each one and understand what it means and why it matters.

### Section 1: DOS Header

**What you'll see:**
```
******* DOS HEADER *******
    0x5A4D  Magic number
    0x3C    File address of new exe header (e_lfanew)
```

**What it means:**
The DOS Header is a leftover from the 1980s when DOS was the operating system. Every Windows PE file still has this header for backward compatibility. The magic number `0x5A4D` is the ASCII code for "MZ" (the initials of Mark Zbikowski, one of the original DOS developers).

**Why it's useful:**
- The magic number confirms this is actually a PE file (if it's not `0x5A4D`, something is wrong)
- The `e_lfanew` value tells us where the real PE headers start (usually around byte 0x80 or so)
- If someone has tampered with a file, this might be corrupted

**Real-world example:**
If you're investigating a file that won't run, and you see the magic number is wrong, the file is corrupted or isn't actually an executable.

### Section 2: NT Headers and File Header

**What you'll see:**
```
******* NT HEADERS *******
    Signature: 0x4550

******* FILE HEADER *******
    0x8664  Machine
    0x6     Number of Sections
    0x5F2A3B1C  Time Stamp
    0x0     Pointer to Symbol Table
    0x0     Number of Symbols
    0xF0    Size of Optional Header
    0x22    Characteristics
```

**What it means:**

- **Signature 0x4550**: This is "PE" in ASCII, confirming we have a valid PE file
- **Machine 0x8664**: This tells us the CPU architecture
  - `0x014C` = 32-bit x86 (Intel/AMD 32-bit)
  - `0x8664` = 64-bit x64 (Intel/AMD 64-bit)
  - `0x01C0` = ARM (for Windows on ARM devices)
- **Number of Sections**: How many sections (code, data, resources) are in the file
- **Time Stamp**: When the file was compiled (in Unix timestamp format)
- **Characteristics**: A set of flags telling us about the file
  - Is it an executable or a DLL?
  - Is it a system file?
  - Can it be relocated in memory?

**Why it's useful:**
- **Compatibility**: You immediately know if a 32-bit program won't run on your system, or vice versa
- **Forensics**: The timestamp can tell you when malware was compiled (though attackers can fake this)
- **File type identification**: You can tell if you're looking at a program or a library

**Real-world example:**
If you're on a 64-bit Windows and a program won't run, checking the Machine field might reveal it's a 32-bit program that requires 32-bit libraries you don't have installed.

### Section 3: Optional Header

**What you'll see:**
```
******* OPTIONAL HEADER *******
    Magic: 0x20B (PE32+)
    Major Linker Version: 0xE
    Minor Linker Version: 0x1D
    Size Of Code: 0x1000
    Size Of Initialized Data: 0x2000
    Size Of Uninitialized Data: 0x0
    Address Of Entry Point: 0x1400
    Base Of Code: 0x1000
    Image Base: 0x140000000
    Section Alignment: 0x1000
    File Alignment: 0x200
    Size Of Image: 0x5000
    Size Of Headers: 0x400
    Subsystem: 0x3
    DllCharacteristics: 0x8160
```

**What it means:**

- **Magic**: Confirms whether this is PE32 (32-bit) or PE32+ (64-bit)
- **Size Of Code**: How many bytes of executable code are in the file
- **Address Of Entry Point**: Where the program starts executing (very important for reverse engineering)
- **Image Base**: The preferred memory address where Windows should load this program
  - Typical values: `0x400000` for 32-bit EXEs, `0x140000000` for 64-bit EXEs
  - DLLs usually use different addresses to avoid conflicts
- **Section Alignment**: How sections are aligned in memory (usually 0x1000 = 4096 bytes)
- **File Alignment**: How sections are aligned on disk (usually 0x200 = 512 bytes)
- **Subsystem**: What kind of program this is
  - `0x2` = Windows GUI application (has windows)
  - `0x3` = Windows console application (command-line)
  - `0x1` = Native driver
- **DllCharacteristics**: Security features enabled
  - ASLR (Address Space Layout Randomization) - makes exploits harder
  - DEP (Data Execution Prevention) - prevents code execution in data areas
  - High Entropy ASLR - even stronger randomization

**Why it's useful:**
- **Security analysis**: You can see if modern security features are enabled. Old or malicious files often lack these protections
- **Debugging**: The entry point tells you exactly where to start looking in a disassembler
- **Memory analysis**: If you're debugging or doing memory forensics, you need to know where the program loads

**Real-world example:**
If you're analyzing malware and you see DllCharacteristics is 0x0 or very low, it means the malware was compiled without modern protections, which might indicate an older malware family or amateur development.

### Section 4: Data Directories

**What you'll see:**
```
******* DATA DIRECTORIES *******
    Export Directory        RVA: 0x0; Size: 0x0
    Import Directory        RVA: 0x2000; Size: 0x150
    Resource Directory      RVA: 0x3000; Size: 0x500
    Exception Directory     RVA: 0x0; Size: 0x0
    Security Directory      RVA: 0x0; Size: 0x0
    Base Relocation Table   RVA: 0x4000; Size: 0x200
    Debug Directory         RVA: 0x0; Size: 0x0
    ...
```

**What it means:**

This is like a table of contents. Each directory points to a specific data structure:

- **Export Directory**: Functions this file provides to other programs (only in DLLs usually)
- **Import Directory**: Functions this file needs from other DLLs (almost every file has this)
- **Resource Directory**: Icons, dialogs, strings, images embedded in the file
- **Base Relocation Table**: Information needed if the program can't load at its preferred address
- **Debug Directory**: Path to debugging symbols (PDB files)
- **TLS Directory**: Thread Local Storage initialization
- **Import Address Table (IAT)**: Where imported function addresses are stored at runtime

An RVA of 0x0 and Size of 0x0 means that directory doesn't exist in this file.

**Why it's useful:**
- **Quick capability check**: If Import Directory exists, you can see what the program does. If Export Directory exists, this is a library
- **Resource extraction**: You can find where embedded files, icons, or strings are located
- **Relocation analysis**: If Base Relocation Table is missing from a DLL, it must load at a specific address (rare and suspicious)

**Real-world example:**
You're investigating why a program has a suspicious icon. The Resource Directory RVA tells you where to look in the file to extract that icon and analyze it.

### Section 5: Section Headers

**What you'll see:**
```
******* SECTION HEADERS *******
    .text
        Pointer To Raw Data: 0x00000400
        Size Of Raw Data:    0x00001000
        Virtual Address:     0x00001000
        Virtual Size:        0x00000C80
        Characteristics:     0x60000020

    .data
        Pointer To Raw Data: 0x00001400
        Size Of Raw Data:    0x00000200
        Virtual Address:     0x00002000
        Virtual Size:        0x00000150
        Characteristics:     0xC0000040

    .rsrc
        Pointer To Raw Data: 0x00001600
        Size Of Raw Data:    0x00000400
        Virtual Address:     0x00003000
        Virtual Size:        0x000003A0
        Characteristics:     0x40000040
```

**What it means:**

Each section is a container for a specific type of data:

**Common section names:**
- **.text** - Executable code (the actual program instructions)
- **.data** - Initialized global variables and static data
- **.rdata** - Read-only data (constants, string literals)
- **.rsrc** - Resources (icons, dialogs, images)
- **.reloc** - Relocation information
- **.pdata** - Exception handling data (64-bit programs)

**Section fields explained:**
- **Pointer To Raw Data**: Where this section starts in the file on disk (in bytes from the beginning)
- **Size Of Raw Data**: How big the section is in the file
- **Virtual Address**: Where this section will be in memory when the program runs
- **Virtual Size**: How big the section is in memory
- **Characteristics**: Permissions and properties
  - `0x20000000` = Contains executable code
  - `0x40000000` = Contains initialized data (readable)
  - `0x80000000` = Contains writable data
  - `0x60000020` = Executable + Readable code (typical for .text)
  - `0xC0000040` = Readable + Writable data (typical for .data)

**Why it's useful:**

1. **Finding the code**: The .text section is where all the executable instructions are. If you're using a disassembler, start here.

2. **Detecting anomalies**: 
   - If Virtual Size is much larger than Raw Size, the section expands in memory (common in packers/malware)
   - If a section is both writable AND executable, that's unusual and potentially dangerous (self-modifying code)
   - Unusual section names like .UPX or .aspack indicate known packers

3. **Memory layout**: You can see how the program is organized in memory

**Real-world example:**

Imagine you see this:
```
.text
    Size Of Raw Data:    0x00001000  (4 KB on disk)
    Virtual Size:        0x00050000  (320 KB in memory)
```

This huge difference means the section unpacks or decompresses itself at runtime. This is a strong indicator of a packed executable, which could be legitimate (to save space) or malicious (to hide from antivirus).

### Section 6: Imported DLLs and Functions

**What you'll see:**
```
Imported DLLs and functions:
  KERNEL32.dll:
    CreateFileW
    ReadFile
    WriteFile
    CloseHandle
    GetCurrentProcess
    
  USER32.dll:
    MessageBoxW
    CreateWindowExW
    
  ADVAPI32.dll:
    RegOpenKeyExW
    RegSetValueExW
    RegCloseKey
    
  WS2_32.dll:
    WSAStartup
    socket
    connect
    send
    recv
```

**What it means:**

This section lists every external function the program uses from Windows system libraries. Think of it as a shopping list of capabilities.

**Common DLLs and what they mean:**

- **KERNEL32.dll**: Core Windows functions
  - File operations: CreateFile, ReadFile, WriteFile
  - Process/thread management: CreateProcess, CreateThread
  - Memory management: VirtualAlloc, HeapAlloc

- **USER32.dll**: User interface functions
  - Window creation: CreateWindow, ShowWindow
  - Message handling: MessageBox, SendMessage
  - Input: GetAsyncKeyState (keyboard), GetCursorPos (mouse)

- **ADVAPI32.dll**: Advanced Windows services
  - Registry: RegOpenKey, RegSetValue
  - Security: LookupAccountName, AdjustTokenPrivileges
  - Services: OpenSCManager, CreateService

- **WS2_32.dll**: Network functions (Winsock)
  - Socket creation and communication
  - Network connections
  - Data transfer

- **WININET.dll**: High-level internet functions
  - InternetOpen, InternetOpenUrl
  - HTTP requests
  - FTP operations

**Why it's useful:**

This is often THE MOST IMPORTANT part for understanding what a program does:

1. **Capability identification**: You can instantly see if a program:
   - Accesses files (CreateFile, ReadFile, WriteFile)
   - Connects to the network (socket, connect, InternetOpenUrl)
   - Modifies the registry (RegSetValue)
   - Creates other processes (CreateProcess)
   - Allocates executable memory (VirtualAlloc)

2. **Malware analysis**: Suspicious import combinations:
   
   **Code injection pattern:**
   ```
   VirtualAllocEx       (allocate memory in another process)
   WriteProcessMemory   (write code to that memory)
   CreateRemoteThread   (execute that code)
   ```
   This is how malware injects itself into legitimate processes.
   
   **Keylogger pattern:**
   ```
   SetWindowsHookEx     (install keyboard hook)
   GetAsyncKeyState     (check if key is pressed)
   CreateFile           (save keystrokes to file)
   ```
   
   **Ransomware pattern:**
   ```
   CryptAcquireContext  (cryptography)
   CryptEncrypt         (encrypt data)
   FindFirstFile        (scan directories)
   SetFileAttributes    (modify file properties)
   ```
   
   **Persistence pattern:**
   ```
   RegOpenKeyEx         (open registry key)
   RegSetValueEx        (modify startup registry entry)
   ```
   This makes malware run every time Windows starts.

3. **Troubleshooting**: If a program won't run and you see it imports from a DLL you don't have, that's your problem.

4. **Reverse engineering**: Imported functions give you clues about program logic before you even open a disassembler.

**Real-world example:**

You analyze an unknown executable and see:
```
KERNEL32.dll:
    VirtualAllocEx
    WriteProcessMemory
    CreateRemoteThread
ADVAPI32.dll:
    RegSetValueExW
WS2_32.dll:
    connect
    send
    recv
```

From this alone, you can deduce: This program probably injects code into other processes, establishes persistence through the registry, and communicates over the network. That's highly suspicious behavior that warrants deeper investigation.

**Real-world example:**

You analyze an unknown executable and see:
```
KERNEL32.dll:
    VirtualAllocEx
    WriteProcessMemory
    CreateRemoteThread
ADVAPI32.dll:
    RegSetValueExW
WS2_32.dll:
    connect
    send
    recv
```

From this alone, you can deduce: This program probably injects code into other processes, establishes persistence through the registry, and communicates over the network. That's highly suspicious behavior that warrants deeper investigation.

## Complete Analysis Workflow: Putting It All Together

Here's how you'd use this tool in a real scenario:

### Scenario: You receive a suspicious file named "invoice.exe"

**Step 1: Run the parser**
```
pe_parser.exe invoice.exe
```

**Step 2: Check the basics (File Header)**
- Is it 32-bit or 64-bit?
- When was it compiled? (Old timestamp on a "new" invoice is suspicious)
- Does the architecture match what you'd expect?

**Step 3: Check security features (Optional Header)**
- Look at DllCharacteristics
- No ASLR or DEP? Red flag for modern software

**Step 4: Examine sections (Section Headers)**
- Are section names normal (.text, .data, .rsrc)?
- Or are they weird (UPX0, .packed, random names)?
- Is Virtual Size >> Raw Size in any section? (Indicates unpacking)
- Are any sections both writable AND executable? (Self-modifying code)

**Step 5: Analyze imports (Import Table) - The most important step**
- Does it import VirtualAllocEx, WriteProcessMemory? (Code injection)
- Does it import networking functions? (Why would an invoice need network access?)
- Does it import registry functions? (Why would an invoice modify the registry?)
- Does it import cryptography functions? (Could be ransomware)

**Step 6: Make your determination**
Based on all the evidence, you can now decide if this file is:
- Legitimate
- Suspicious and needs deeper analysis
- Clearly malicious

## Example Analysis Results

Let's look at two real examples:

### Example 1: Legitimate Program (notepad.exe)

**File Header:**
- Machine: 0x8664 (64-bit) ✓
- Timestamp: Recent date ✓
- Characteristics: Normal executable ✓

**Sections:**
- .text (code)
- .data (data)
- .rsrc (resources)
- All normal names ✓
- No size anomalies ✓

**Imports:**
- KERNEL32.dll: CreateFile, ReadFile, WriteFile (file operations ✓)
- USER32.dll: CreateWindow, MessageBox (UI functions ✓)
- GDI32.dll: Drawing functions ✓

**Conclusion:** This is clearly a legitimate text editor. All imports make sense for a simple editor.

### Example 2: Suspicious File (found on infected system)

**File Header:**
- Machine: 0x014C (32-bit) 
- Timestamp: 1970 (fake/suspicious)
- Characteristics: Executable

**Sections:**
- UPX0 (packed section name - red flag)
- UPX1 (another packed section - red flag)
- Virtual Size: 0x50000, Raw Size: 0x1000 (huge difference - red flag)

**Imports:**
- KERNEL32.dll: 
  - VirtualAllocEx (allocate memory in other processes - red flag)
  - WriteProcessMemory (write to other processes - red flag)
  - CreateRemoteThread (execute code in other processes - red flag)
- ADVAPI32.dll:
  - RegSetValueEx (modify registry - suspicious in combination)
- WS2_32.dll:
  - connect, send, recv (network communication - suspicious in combination)

**Conclusion:** This file exhibits multiple red flags:
1. Packed/compressed (UPX packer)
2. Code injection capabilities
3. Registry modification
4. Network communication
5. Fake timestamp

This is almost certainly malware and should be analyzed in a sandbox environment.

## Outhput Screenshots Section

Below are example screenshots of the tool in action analyzing different types of files.

### Screenshot 1

<img width="531" height="310" alt="image" src="https://github.com/user-attachments/assets/1d4fe3a9-1de6-4e1f-803c-463054a7f7b5" />




---

### Screenshot 2

<img width="555" height="341" alt="image" src="https://github.com/user-attachments/assets/0e00e4d5-eca9-4841-a28b-8ed01c447fd8" />



---

### Screenshot 3

<img width="502" height="359" alt="image" src="https://github.com/user-attachments/assets/aeee4c94-51c1-45c8-9f6d-626fbfd64928" />




---

### Screenshot 4

<img width="498" height="361" alt="image" src="https://github.com/user-attachments/assets/427e15d7-163d-4ba9-bcec-9ead32c5984f" />




---


## Important Safety Warning

If you're analyzing unknown or suspicious files, always do it safely:

- Use a virtual machine (like VirtualBox or VMware)
- Don't connect that virtual machine to the internet
- Take a snapshot before you start so you can restore it
- Never analyze suspicious files on your main computer

This tool only READS files - it never executes them. But still, it's good practice to work in an isolated environment.

## What This Tool Doesn't Do

To be clear about limitations:

- It doesn't detect if a file is malicious (that requires more analysis)
- It doesn't unpack packed executables (it shows you they're packed, but doesn't unpack them)
- It doesn't examine resources like icons or dialogs
- It doesn't verify digital signatures
- It only shows what's in the file, not what the program does when it runs

This is a "static analysis" tool - it looks at the file as data. To understand what a program actually does, you'd need to run it (in a safe environment) or use a debugger.


## Technical References

If you want to learn more about PE files:

- Microsoft has official documentation about the PE format on their developer website
- The Wikipedia article on "Portable Executable" is actually quite good
- There are more advanced tools like PE-bear if you want a graphical interface

## Final Thoughts

Understanding PE files is like learning to read the "DNA" of Windows programs. It's a fundamental skill in security, reverse engineering, and even regular software development. This tool gives you a way to start learning without needing expensive software or deep expertise.

The best way to learn is to run this program on various files and see what they contain. Try it on Windows programs, try it on simple programs you write yourself, and gradually you'll build intuition for what's normal and what's suspicious.

Remember: this tool is for learning and legitimate analysis only. Always respect copyright and don't use it for anything unethical or illegal.
