# Windows-PE-Injection
PE Injection with ring3 hook bypass

Overview
1. Resolve NtApi calls by manually mapping ntdll. This will ensure that we use ring3 hook free functions later on.
2. Create new process that we are going to inject our PE using RtlCreateUserProcess.
3. Get the size of the PE image that we are injecting.
4. Allocate block of data using NtCreateSection & NtMapViewOfSection.
5. Copy the PE image into newly allocated block of data (remote and local section).
6. Relocate PE image.
7. Execute our code (Two ways : Use NtSetContextThread to change the EAX register to the entry point of injected PE or write a jump from the process entry point to our injected PE entry point.
