Ghidra
======

[![Build Status](https://codevision.visualstudio.com/Ghidra/_apis/build/status/kant2002.Ghidra?branchName=master)](https://codevision.visualstudio.com/Ghidra/_build/latest?definitionId=92&branchName=master)

Let's build me!

# How to build

Instructions pretty simple.

```
cd Ghidra
mvn package
```

There assumption that root of this repository is same as root of unpacked Ghidra distribution. This allow magic to happens. 
I need more time to put all supplementary code to the source control and generate proper build pipeline.

**CAUTION**
If you want to compile Ghidra using Gradle you have to wait a bit until RuntimeScripts module would be published. 
This is essentially command line scripts as far as I aware. Reason why do you need them, is that `support/LaunchSupport.jar`
perform detection of Development/Production environment based on the presence of `build.gradle` in the root folder. 

# Issues

- Runtime support scripts for launching Ghidra is missing

# Update processor manuals
To update all processor manuals run 

    bash ./tools/update-manuals.sh

See https://github.com/NationalSecurityAgency/ghidra/issues/38 for more information.

# Alternative processors

- https://github.com/tom-seddon/Ghidra6502