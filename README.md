# InjectTools

A header-only injector helper for your personal projects. Nothing crazy — just bare-bones essentials you need to load a DLL or raw shellcode into a remote process. There are probably a million projects just like this -- I just wanted to have my own to tinker with and use.

`injector.c` is included purely as a usage example; the implementation is in `inject_tools.h`. Feel free to grab the header and drop it into any project where you need an injector ASAP. This was made mostly by pulling together parts,concepts, and ideas from other injectors I have made in the past and then generalizing the implementations so that they are reusable. No testing has been done on it, so if you grab it and something doesn't work, let me know! I'll be testing it as I use it in other personal projects.

## Usage

To use it, just include the header:

```c
#include "inject_tools.h"
```

## Functions

- `GetPIDByName` -- Get the process ID of a target process by using it's name  
- `GetDLLPayload` / `GetShellcodePayload` -- Automates the process of reading a payload from shellcode or getting the full-path name of a DLL so they can be written into the target process
- `InjectDLL` / `InjectShellcode` -- Write the payload into the target process  
- `RunPayloadDLL` / `RunPayloadShellcode` -- spin up a remote thread to run your payload in the target process. 

## Disclaimer

This code is provided as-is, with no warranty. I accept no responsibility for how it’s used. You’re free to incorporate it into your own projects. Windows defender and other AV products may flag this. Anti-cheats will likely catch this. Use at your own risk.

---

Enjoy, and happy injecting!