# Introduction
This is the first level of the general challenge, so the developers gave the username and password that may be used to log into the SSH server which is called narnia.labs.overthewire.org, on port 2226 TCP.
The username and password are both "**narnia0**".

# The Challenge

## Overview

Navigating to the **/narnia/** directory, multiple executable files and their respective C language sources are visible, and that's the general structure of the Narnia levels: going to this path and exploring some vulnerability of an executable binary that specifically leads you to privilege escalation. 

Talking about binaries, the interesting one is the "**narnia0**" ELF file.
Running it, it's possible to see a confusing text message with an input from the terminal:
<img width="501" height="151" alt="image" src="https://github.com/user-attachments/assets/f21a3e24-73bf-4bb1-aa56-af2b11efe17f" />

The program wants us to correct "val's" value from ```0x41414141``` to ```0xdeadbeef```, and in sequence asks for an input text. It seems like it will elevate us to the ```narnia1``` user if we give it the right input.

## Code Analysis

All source files for each challenge are already placed in the ```/narnia/``` directory. In the ```narnia0.c``` file, it is possible to see this code:

```c
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

The code firstly declares two variables in sequence: 

* "val": with the long type;
* "buf":  which is a string of 20 bytes  - or 20 characters - in size.

```c
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];
```

Then it prints out the initial message and - strangely - reads a 24 bytes sized string input - which means 24 characters - into the ```buf``` variable memory.

```c
printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
printf("Here is your chance: ");
scanf("%24s",&buf);
```

In sequence the program prints out both ```buf```'s and ```val```'s values and reaches an important part of the code.

```c
 if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
 }
 else {
     printf("WAY OFF!!!!\n");
     exit(1);
 }
```

In this part the program is doing a comparison between *val*'s value and the literal number ```0xdeadbeef```, also mentioned in a *printf* above. If the numerical value inside *val* corresponds to ```0xdeadbeef``` (3735928559 in decimal), it sets the ***real user id*** (the user who executed the program) to the **effective user ID** (the user who owns the program file), and spawns a shell with *sh*.

Now, let's draw some conclusions with all this information about the code.

* First, the obvious "trickery" here is that we are supposed to change the *val*'s value with our input, but it is never actually loaded into the variable. Instead, it is placed into a 20-byte char buffer. So it's logical that, no matter how many tries we give in the input, we will never change the real value inside *val*. Well, at least if we play fair.
* Later, if we "magically" change *val* to ```0xdeadbeef```, the program will spawn a shell with the **effective user id** of the file. Looking at the binary file details with ```ls -la``` we can see that this little part of the code will grant us the victory over the level, since the **effective user** of the program is the next level user **narnia1**:

<img width="506" height="59" alt="image" src="https://github.com/user-attachments/assets/f001c431-4ba6-426c-ae9e-904cdb86838f" />

So it seems that the challenge here is to set the "***val***" value to "***0xdeadbeef***", using the only way we have into the program's memory: the "***buf***" variable. But how?

## Exploitation

### How Memory Stack Works

First of all, we need to remember how all the program's data is arranged in memory. 

All programs have something called "**stack**". The stack is a program-owned zone of the memory where all variables, literal data and other useful information are placed at runtime, each one with its own address. It has a well-defined top - a specific memory address - that puts a "limit" to the program memory. Each time a variable is declared or some data is created at runtime, a new memory address is "acquired" by the program, **below the stack top**. 

Let's say our program just started: the kernel defines a stack top for our program, but at this point, we have not created any variable or data, so the stack is supposed to be empty.

<img width="461" height="170" alt="image" src="https://github.com/user-attachments/assets/56dba7c2-9755-4efc-9ccf-fae71d307d12" />


By the end of the program's execution, many variables have been created and the program's stack grew downward - below the stack - with different space sizes and data types, but the program stack top still has the same address. So the stack will look something like this:

<img width="357" height="255" alt="image" src="https://github.com/user-attachments/assets/8abe240b-076c-4525-b687-ac1335a2f1dd" />


Look how the top is the same as before, but many addresses have appeared in the program's stack, increasing its size.

* PS: It is important to note that the fact that stack addresses increase "downward" with each declared variable does not imply that the information is placed "in reverse" in memory.

So instead of an address defining where the program memory starts, the stack top defines where it ends. Each variable's memory address defines where, below the top, the information bits are supposed to start. 

### Understanding The Actual Challenge

Now that you superficially understand how data is arranged in the stack, look at the order in which the two variables we have in **narnia0.c** are declared:

```c
long val=0x41414141;
char buf[20];
```

First *val* is declared, and then *buf*. So - abstracting other information used by the program, for didactic purposes - we can visualize the stack "storing" these variables in this way:

<img width="741" height="407" alt="image" src="https://github.com/user-attachments/assets/ce8689e8-7306-4506-bdcb-e9576c6f6e85" />


Remember that variable declaration always implies the use of lower and lower addresses to define its beginning, and that's why "buf" is below "val".

As we can see in the code, "buf" only stores 20 bytes but the input requires 24 bytes. If we enter a 20 byte or less sized input, the data is just correctly stored. Now, you should definitely be asking yourself: "what would happen to the memory if we enter the extra 4 bytes - allowed by *scanf* - in the input?" And that's a nice question.

The data will not be "pulverized" or "go to trash". Actually, it will be stored in memory, but not in the right allocated space. Instead, it will "overflow" the variable's available space and invade the space above it! This means that if we intentionally put a value larger than *buf*'s size, like 24 bytes, the extra 4 bytes will be written over 4 bytes of *val*'s value, allowing us to pass the challenge!

The scanf in *narnia0* converts each byte of the input into a char, which actually stores a byte representing the ASCII code of the character. Since ```0xdeadbeef``` is an 8-digit hexadecimal number, we can write it as 4 separate bytes: 0xde, 0xad, 0xbe and 0xef. Don't think too much about this slicing; all these bytes will be stored together in memory recomposing the original number.

### Getting Our Hands Dirty

So I wrote this little program in C to print out 20 garbage characters, and the extra bytes at the end:

```c
#include <stdio.h>

int main(){//20 garbage characters just to fill "buf" memory and cause overflow
	printf("aaaaaaaaaaaaaaaaaaaa");
    printf("%c%c%c%c", 0xef, 0xbe, 0xad, 0xde); //bytes in reverse for little-endian
	return 0;
}
```

Now, we just have to save this program in a writable directory (like under /tmp). Naturally, we need to redirect our exploit output to *narnia0*, so we could try this:

```bash
$> ./exploit | /narnia/narnia0
```

only to notice that we didn't receive an error message, but a shell has not spawned as narnia1:

<img width="505" height="98" alt="image" src="https://github.com/user-attachments/assets/6f9d3c81-5a50-4344-a8dc-51475054015f" />


Let's examine what is happening here:

* First, our exploit prints out our bytes into the input of narnia0, writing over *val* (using the pipeline);
* Later, the shell is actually spawned by narnia0, using the pipeline as STDIN;
* In sequence, our exploit program ends and the pipeline is closed, sending EOF (End Of File) to the shell input;
* Our shell immediately dies for not having any STDIN.

So the final goal here is to keep the pipe alive, sending our inputs to the newly spawned shell, and we can do it using *cat* (which repeats all input as output, when used without arguments):

```bash
$> (./exploit; cat) | /narnia/narnia0
```

And there it is:

<img width="575" height="147" alt="image-20260214230132563" src="https://github.com/user-attachments/assets/b21ee224-d351-4ad5-bb60-75ad5e2ceb79" />

# Rechapter

This was a really fun challenge that instigates us to think about many themes, from process memory to some Linux shell advanced usage. Hope to see you in the next level writeup.

