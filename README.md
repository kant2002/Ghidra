Ghidra
======

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
 