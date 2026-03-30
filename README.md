# Process Hollowing
A basic C source to process hollow, using hardcoded target &amp; source executables

Compile using windows command line:
- call vcvars64.bat to prepare the environment
- `cl hollow.c`
Done.

In order to execute it, you need a `lala.exe` file in the current folder. 
It will execute the lala.exe file and inside that, there will be loaded the contents of powershell.exe. Finally you will have a powershell process with the name of lala.exe
