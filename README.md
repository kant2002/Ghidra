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

Compare built Ghidra with released version. In PowerShell only (could be Powershell Core on Linux)

    ./tools/compare.ps1 -GhidraLocation "C:\ghidra"

# Alternative processors

- https://github.com/tom-seddon/Ghidra6502
- https://github.com/andr3colonel/ghidra_wasm WASM support
- https://github.com/xyzz/ghidra-mep Toshiba MeP processor
- https://github.com/beardypig/ghidra-emotionengine Play Station 2's Emotion Engine MIPS based CPU
- https://github.com/Thog/ghidra_falcon Nvidia Falcon processors
- https://github.com/aldelaro5/ghidra-gekko-broadway-lang Gekko and Broadway CPU variant used in the Nintendo GameCube and Nintendo Wii respectively
- https://github.com/kotcrab/ghidra-allegrex Allegrex CPU
- https://github.com/beardypig/ghidra-chip8 CHIP8 virtual machine
- https://github.com/Nitori-/SleighGB LR35902

# Additional loaders
- https://github.com/JayFoxRox/ghidra-xbox-extensions Tools to analyze original Xbox files
- https://github.com/jogolden/GhidraPS4Loader PlayStation4 binaries
- https://github.com/Adubbz/Ghidra-Switch-Loader Loader of Nintendo Switch formats
- https://github.com/idl3r/GhidraVmlinuxLoader Loader for vmlinux kernel images
- https://github.com/lab313ru/ghidra_sega_ldr Sega Mega Drive / Genesis ROMs loader
- https://github.com/Maschell/GhidraRPXLoader RPX/RPL loader
- https://github.com/NeatMonster/mclf-ghidra-loader MobiCore Loadable Format (MCLF) used by trustlet and driver binaries