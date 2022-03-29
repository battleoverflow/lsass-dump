# LSASS Dumper
Simple LSASS Dumper created using C++ as an alternative to using Mimikatz memory dumper.

NOTE: You still need Mimikatz installed to read the dumped data. This program only dumps the data.

VirusTotal Scan Results: 2/71 when running against the executable build (For personal/experimental use only)

## Usage
The easiest way to build the executable is to just run the `Dump.cpp` file in Visual Studio, but if you prefer `g++`, that should work too.

After compiling the code into an executable, run it!

You can run the executable either way:
```powershell
> ./Dump.exe
or
> ./Dump.exe Output.txt
```
NOTE: If no argument is specified, your file will be `HOSTNAME_M_D_YYYY.txt`

Here are the commands you will need to use in Mimikatz to access the dumped data:
```powershell
> mimikatz # This will start the program
mimikatz$ sekurlsa::minidump <FileName>
mimikatz$ sekurlsa::logonPasswords
```