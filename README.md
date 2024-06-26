checksec
========

## Bash version entering feature freeze

Checksec is a bash script to check the properties of executables (like PIE, RELRO, Canaries, ASLR, Fortify Source).
It has been originally written by Tobias Klein and the original source is available here: http://www.trapkit.de/tools/checksec.html


Updates
-------
  ** Version 2.7.x should be the last version of checksec in bash

  Version 3.x will be released as a golang static binary
  Checksec was originally released with 1.0 in early 2009 and has been used for validating binary checks of Linux systems for over a decade. Over time as more checks were supported and Linux distributions have changed, this has brought more dependencies into checksec. Adding more and more dependenies to be able to check the security flags of files, it not an ideal solution for systems with minor dependencies including embedded systems, distroless containers, and cross platform checks.
  - Feature partial between the bash version and the golang version will be mostly supported.
    - Adding support for yaml output
    - Removing support for CSV
    - JSON and XML will still both be supported
  - Much faster results. When checking 694 files in a directory
      - bash: real  0m10.348s
      - golang: real    0m0.691s
  - Adds recursive directory support
  TODO:
  - [X] Fix Partial RELRO
  - [ ] Add fortify file function results
  - [ ] Add fortifyProc
  - [ ] Add ProcLibs
  - [ ] Add selinux checks
  - [ ] Add additional kernel flag checks
  - [ ] Update and Validate all current tests
  - [ ] Enable golint validation

For OSX
-------
 Most of the tools do not work on mach-O binaries or the OSX kernel, so it is not supported

**Cosign Verify Checksec**

`cosign verify-blob --signature checksec_new.sig --certificate checksec_new.pub checksec --certificate-identity=slimm609@gmail.com --certificate-oidc-issuer=https://github.com/login/oauth`

**Openssl Verify Checksec**
Openssl verification is being deprecated in favor of Cosign Verification, which is backed by a hardware security module and provides a greater level of intergrity.

`openssl dgst -sha256 -verify checksec.pub -signature checksec.sig checksec`

Examples
--------

**normal (or --format=cli)**

    $checksec --file=/bin/ls
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /bin/ls

**csv**

    $ checksec --output=csv --file=/bin/ls
    Partial RELRO,Canary found,NX enabled,No PIE,No RPATH,No RUNPATH,/bin/ls

**xml**

    $ checksec --output=xml --file=/bin/ls
    <?xml version="1.0" encoding="UTF-8"?>
    <file relro="partial" canary="yes" nx="yes" pie="no" rpath="no" runpath="no" filename='/bin/ls'/>

**json**

    $ checksec --output=json --file=/bin/ls
    { "file": { "relro":"partial","canary":"yes","nx":"yes","pie":"no","rpath":"no","runpath":"no","filename":"/bin/ls" } }

**Fortify test in cli**

    $ checksec --fortify-proc=1
    * Process name (PID)                         : init (1)
    * FORTIFY_SOURCE support available (libc)    : Yes
    * Binary compiled with FORTIFY_SOURCE support: Yes

    ------ EXECUTABLE-FILE ------- . -------- LIBC --------
    FORTIFY-able library functions | Checked function names
    -------------------------------------------------------
    fdelt_chk                      | __fdelt_chk
    read                           | __read_chk
    syslog_chk                     | __syslog_chk
    fprintf_chk                    | __fprintf_chk
    vsnprintf_chk                  | __vsnprintf_chk
    fgets                          | __fgets_chk
    strncpy                        | __strncpy_chk
    snprintf_chk                   | __snprintf_chk
    memset                         | __memset_chk
    strncat_chk                    | __strncat_chk
    memcpy                         | __memcpy_chk
    fread                          | __fread_chk
    sprintf_chk                    | __sprintf_chk

    SUMMARY:

    * Number of checked functions in libc                : 78
    * Total number of library functions in the executable: 116
    * Number of FORTIFY-able functions in the executable : 13
    * Number of checked functions in the executable      : 7
    * Number of unchecked functions in the executable    : 6


**Kernel test in Cli**

    $ checksec --kernel
    * Kernel protection information:

    Description - List the status of kernel protection mechanisms. Rather than
    inspect kernel mechanisms that may aid in the prevention of exploitation of
    userspace processes, this option lists the status of kernel configuration
    options that harden the kernel itself against attack.

    Kernel config: /proc/config.gz

        GCC stack protector support:            Enabled
        Strict user copy checks:                Disabled
        Enforce read-only kernel data:          Disabled
        Restrict /dev/mem access:               Enabled
        Restrict /dev/kmem access:              Enabled

    * Kernel Heap Hardening: No KERNHEAP

    The KERNHEAP hardening patchset is available here:
     https://www.subreption.com/kernheap/


**Kernel Test in XML**

    $ checksec --output=xml --kernel
    <?xml version="1.0" encoding="UTF-8"?>
    <kernel config='/boot/config-3.11-2-amd64' gcc_stack_protector='yes' strict_user_copy_check='no' ro_kernel_data='yes' restrict_dev_mem_access='yes' restrict_dev_kmem_access='no'>
        <kernheap config='no' />
    </kernel>

**Kernel Test in Json**

    $ checksec --output=json --kernel
     { "kernel": { "KernelConfig":"/boot/config-3.11-2-amd64","gcc_stack_protector":"yes","strict_user_copy_check":"no","ro_kernel_data":"yes","restrict_dev_mem_access":"yes","restrict_dev_kmem_access":"no" },{ "kernheap_config":"no" } }

Using with Cross-compiled Systems
---------------------------------------
The checksec tool can be used against cross-compiled target file-systems offline.  Key limitations to note:
* Kernel tests - require you to execute the script on the running system you'd like to check as they directly access kernel resources to identify system configuration/state. You can specify the config file for the kernel after the -k option.

* File check -  the offline testing works for all the checks but the Fortify feature.  Fortify, uses the running system's libraries vs those in the offline file-system. There are ways to workaround this (chroot) but at the moment, the ideal configuration would have this script executing on the running system when checking the files.

The checksec tool's normal use case is for runtime checking of the systems configuration.  If the system is an embedded target, the native binutils tools like readelf may not be present.  This would restrict which parts of the script will work.

Even with those limitations, the amount of valuable information this script provides, still makes it a valuable tool for checking offline file-systems.
