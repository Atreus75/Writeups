# Main initial ideas
maybe i can ovewrite "ofile" to indicate a file i can read, so i could put "/etc/narnia_pass/narnia4" inside "ifile" and read the contents in another file of my choice.
Maybe i need to put a null-byte inside ifile to stop strcpy in the right position.

### OBS
Remember to considerate all the characters in the path used, like all the 4 chars in `/tmp` etc.
I will start the proper writeup soon.
