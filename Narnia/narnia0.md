# Introduction
This is the first level of the general challenge, so the developers gave the username and password that may be used to log in the SSH server, which is called narnia.labs.overthewire.org, with the 2226 TCP port.
The username and password are both "**narnia0**".

# The Challenge
Navigating to the **/narnia/** directory, multiple executable files and its respective C language sources are visible. The interesting one is the "**narnia0** ELF file.
Running it, its possible to see a confusing text message with an input from terminal:
<img width="501" height="151" alt="image" src="https://github.com/user-attachments/assets/f21a3e24-73bf-4bb1-aa56-af2b11efe17f" />

Reading the narnia.c source file, it is possible to see this code:
```
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```
The challenge here its to set the "***val***" variable value to "***0xdeadbeef***", using the "***buf***" input variable. 
If the values are equally "0xdeadbeef", so the program should spawn a shell with the SUID user privileges, like it is shown in ls:
<img width="506" height="59" alt="image" src="https://github.com/user-attachments/assets/f001c431-4ba6-426c-ae9e-904cdb86838f" />
