---
title: "Smokeloader"
date: 2022-11-23T13:43:53-06:00
draft: false
# tags: ["hugo","smokeloader"]
# series: "How to use poison"
---

<!-- *Poison* is a **clean**, **professional** Hugo theme designed to **captivate** your readers.

It's also **tiny** and **privacy conscious** with *no external dependencies*.  That's right---no JavaScript frameworks, icon packs, or Google fonts.  No ads or trackers polluting your console window (try it out and take a look).  **We kept things simple**.  A little vanilla JavaScript, a dash of CSS, and the power of Hugo.

  **Taxax**.dsc -->



# SmokeLoader


## Introduction

SmokeLoader is a popular bot that has existed since 2011. It is mostly used to deliver other malwares. It keeps evolving and changing, with new features being introduced all the time.

This article was written by me while I was learning about a few popular malware techniques and how the smokeloader leverages them efficiently to avoid AV detection and make binary reversing harder.

The file we'll be looking at is shellcode developed and FASM compiled, making analysis more challenging. This is used by malware to minimize file size in KBs with no imports and evade AV detections.


![image](/posts/images/image1.png)
![image](/posts/images/image2.png)
![image](/posts/images/image3.png)
![image](/posts/images/image4.png)

A few abnormalities that stand out at first glance are high entropy and rwx section permissions.

Now we will reverse the binary and find more on its code structure. 
The initial phase of Smokeloader contains a large amount of junk jump calls that do nothing to advance the code and hence slow down the static analysis work on this sample.

![image](/posts/images/image5.png)

On traversing the jumps, we get few anti-debug checks.
To determine whether the application is in a debugging environment, the PEB is referenced and the `BeingDebugged` and `NtGlobalFlag` flags are read. We can bypass it by patching the return value to 0 for both checks. 
One thing to make a note here is that PEB is moved in the EBX for using it in later stages of the code, and all anti-debug checks referred to PEB from EAX.

![image](/posts/images/image6.png)

Next part of the code loads DLL by accessing PEB to resolve APIs dynamically at run time. The below code will set EDX to the image base address of ntdll.dll by traversing thru the PEB data structure. 


| First          | Last     |
|----------------|----------|
| mov esi,dword ptr ds:[ebx+C]           | ESI = PEB->Ldr     |
| mov esi,dword ptr ds:[esi+1C]          | ESI = PEB->Ldr.InInitializationOrderModuleList.Flink |
| mov edx,dword ptr ds:[esi+8] | EDX = image base of ntdll (LDR_MODULE's BaseAddress) |


![image](/posts/images/image7.png)


To see in little detail, the code gets to the `PEB_LDR_DATA` over the offset `0xC`, 
Over the offset `0x1C` of `PEB_LDR_DATA`, it gets to the pointer of `InInitializationOrderModuleList`
Since ntdll.dll is the first module loaded, it's the first LDR_MODULE entry in `InInitializationOrderModuleList`. 

So with ESI pointing to `PEB`->`Ldr.InInitializationOrderModuleList.Flink`, [ESI+0] points to the list entry's Flink, [ESI+4] points to the list entry's Blink, and [ESI+8] is the BaseAddress value of the first LDR_MODULE entry (ntdll.dll's LDR_MODULE). The below diagram shows the overall data structure.

![image](/posts/images/image8.png)

The next set of code MOV EDI, ESI will position the specific address in the smoke payload and LODSD the hex by making EAX to store specific API HASH 0976055C. 

![image](/posts/images/image9.png)

Later there is a call to API resolution function which will be used to resolve the needed API. The code can be divided into three segments, 
> The first part - Locates the export table of an DLL. 

> The Middle part – Does hashing and compare.

> The Final part - Gets the absolute address of resolved API and moves to a register for later usage. 


![image](/posts/images/image10.png)


We found the ntdll.dll has been retrieved and now we need to parse dll image and find the export table. The first segment of the code will resolve the VA of EAT and is explained in below table.

| First          | Last     |
|----------------|----------|
|add edx,ebx|	|
 |dec ecx| |
|push ecx|	|
|mov esi,[edx+ecx*4]|	[edx+ecx*4] = Array to store entries 4bytes long. ESI = RVA of (n)th entry.|
|add esi,ebx	|ESI= VA of (n)th Name entry.|
|mov eax,esi	|Hashing algorithm|
|xor ecx,ecx||
|xor ch,[eax]||
|rol ecx,8||
|xor cl,ch||
|inc eax	|Incremented the counter|
|cmp [eax],0|	Check if end of name function byte is 0.|
|jne smoke.4013A6|	|
|cmp ecx,ebp|	compare with HASH 0976055C|
|pop ecx|	|
|jne smoke.40139B|	If hash didn't match, jump back to loop, and start for next name function.|
|pop edi|	|
|mov eax,[edi+24]|	EAX= RVA of function ordinal table|
|add eax,ebx|	EAX= VA of function ordinal table|
|movzx ecx,[eax+ecx*2]|	ECX= Get <resolved API> ordinal|
|mov eax,[edi+1C]|	EAX= RVA of AddressOfFunctions or the Export Table|
|add eax,ebx|	EAX= VA of the Exported Table|
|mov eax,[eax+ecx*4]|	EAX= RVA of <resolved API>|
|add eax,ebx|	EAX= VA of <resolved API>|
|mov [esp+1C],eax|	|
|popad|	|
|ret|	|




Middle and last segments of the code is explained below:



As we have statically determined the working process of the code, we can deduce that the resolved API will be stored in EAX, and setting the BP on its return can reveal what API was resolved while dynamically debugged.

![image](/posts/images/image11.png)

First, `zwAllocateVirtualMemory` is resolved from ntdll.dll. This API will be used multiple times later in the code to dump data.

The next call takes us for couple of memory allocations and move some encrypted data from the payload. 


 ![image](/posts/images/image12.png)
 ![image](/posts/images/image13.png)

Later the following call takes us to a piece of shellcode that was already present in raw file memory. The goal of this shellcode is to decrypt the encrypted C2 domain, which is highlighted in red in the image below. The decryption procedure is straightforward and uses the XOR key FF.


![image](/posts/images/image14.png)
![image](/posts/images/image15.png)


It's pretty interesting that VT only has one hit for the C2 address, and the web page is now unavailable.

![image](/posts/images/image16.png)
 
This is not the end of the application, we have only seen half of its ability, and the next section includes numerous hashing, code injection, anti-VM and analysis checks, bot ID creation, and HTTP post action on C2.

Junk code and API Hashing, as well as exploiting the LDR structure to load modules, are tactics I notice more frequently in my study. 

This research has taught us how to identify API hashes and how to efficiently analyse shellcode.

**End of Part 1.**




