
# Table of Contents

-   [Web/Pirate](#orgab8a6e9)
-   [Reversing/segFix](#org7262471)



<a id="orgab8a6e9"></a>

# Web/Pirate

Author: iLoop


### Description

This one is simple you just need to get the /flag :-)


## First Try

    $ curl -s http://io.ept.gg:30070/flag  
    Forbidden, but nice try ;)

If the request contains **flag**, it will be rejected by **filter.py**. This filter does not seem to urldecode the request url. 


### Filter

    from mitmproxy import http
    import re
    
    
    def request(flow):
        if 'flag' in flow.request.url:
            flow.response = http.HTTPResponse.make(403, b"Forbidden, but nice try ;)


## Second Try

By urlencoding a character in **flag** we win!

    $ curl -s http://io.ept.gg:30070/fl%61g  
    EPT{5mugl3r5_liv3_l1k3_k1ng5}


<a id="org7262471"></a>

# Reversing/segFix

Author: vcpo


### Description

Could you please find an input that fixes my segmentation fault? I think I had a way to verify the flag when the binary was still working


## Solution

    $ ./segFix
    Provide input:
    hallaballa
    [1]    2574257 segmentation fault (core dumped)  ./segFix
    $ allaballa
    zsh: command not found: allaballa

Apparently, the program read only one byte at first.

Brute forcing the byte to see if we get different results.

    for i in {0..256}; echo -e "\x$i" | ./segFix
    0 Provide input:
    1 Provide input:
    2 Provide input:
    3 Provide input:
    4 Provide input:
    5 Provide input:
    Input flag for verification:
    It is not a correct flag, unfortunately :(
    6 Provide input:
    7 Provide input:
    8 Provide input:
    9 Provide input:
    10 Provide input:
    ...
    ...

Providing **0x05** as input fixes the segfault.

Static analysis gives nothing but a severe headache, so we can just as well bring out the hammer (gdb).

Started out with **catch syscall**, and continued until reaching the read call.

The program is using the value of the supplied byte as an address offset.

    0x7fffffffdb5d    mov    rax, 0
    0x7fffffffdb64    mov    rdi, 0
    0x7fffffffdb6b    sub    rsp, 1
    0x7fffffffdb6f    mov    rsi, rsp
    0x7fffffffdb72    mov    rdx, 1
    0x7fffffffdb79    syscall   i        // read 
    0x7fffffffdb7b    mov    dil, byte ptr [rsp]
    0x7fffffffdb7f    lea    rax, [rip]  // rax = 0x7fffffffdb86
    0x7fffffffdb86    add    rax, rdi    // rax += 0x05
    0x7fffffffdb89    jmp    rax         

Then we enter a loop that **xor** the next section of the program with **0x90**. This loop continues until we reach a null byte.

    0x7fffffffdb8b    lea    rdi, [rip + 0xc]
    0x7fffffffdb92    xor    byte ptr [rdi], 0x90
    0x7fffffffdb95    mov    al, byte ptr [rdi]
    0x7fffffffdb97    inc    rdi
    0x7fffffffdb9a    cmp    al, 0x90
    0x7fffffffdb9c    jne    0x7fffffffdb92 

We continue the program until we reach another read syscall that is attempting to read 31 bytes.

    0x7fffffffdcc7    mov    rax, 0
    0x7fffffffdcce    mov    rdi, 0
    0x7fffffffdcd5    sub    rsp, 0x1f
    0x7fffffffdcd9    mov    rsi, rsp
    0x7fffffffdcdc    mov    rdx, 0x1f
    0x7fffffffdce3    syscall 

As it happens, a string of 31 bytes has already been pushed onto the stack and **r12** has the address of that string.
It's reasonable to assume that this is related to the flag.

    R12  0x7fffffffda77 ◂— 'EQVxw6jaWd:oekw>~vMp$qsH)jE}isc'

The input string that was placed on the stack is xor'ed with an iterator **rcx**. Then it is xor'ed with the corresponding byte of the string in **r12**. The result is added to **rsi**.

    0x7fffffffdce5    mov    rcx, 0
    0x7fffffffdcec    mov    rsi, 0
    0x7fffffffdcf3    mov    dl, byte ptr [rsp + rcx]
    0x7fffffffdcf6    xor    rdx, rcx
    0x7fffffffdcf9    mov    dil, byte ptr [r12 + rcx]
    0x7fffffffdcfd    xor    dl, dil
    0x7fffffffdd00    add    rsi, rdx
    0x7fffffffdd03    inc    rcx
    0x7fffffffdd06    cmp    rcx, 0x1f
    0x7fffffffdd0a    jne    0x7fffffffdcf3 

If **rsi** is **0** the program will print out the string pointed to by **r14**, if it's not, **r13** will be printed, and then the program exits.

    R13  0x7fffffffdac7 ◂— 'It is not a correct flag, unfortunately :(\n'
    R14  0x7fffffffda97 ◂— 'Wow, you entered the right flag, impressive!\n'

    0x7fffffffdd0c    test   rsi, rsi
    0x7fffffffdd0f    jne    0x7fffffffdd2d                <0x7fffffffdd2d>
    
    0x7fffffffdd11    mov    rax, 1
    0x7fffffffdd18    mov    rdi, 1
    0x7fffffffdd1f    mov    rsi, r14
    0x7fffffffdd22    mov    rdx, 0x2d
    0x7fffffffdd29    syscall 
    0x7fffffffdd2b    jmp    0x7fffffffdd47                <0x7fffffffdd47>
        ↓
    0x7fffffffdd47    mov    rax, 0x3c
    0x7fffffffdd4e    xor    rdi, rdi
    0x7fffffffdd51    syscall  <SYS_exit>
         status: 0x0

Since we know that the input string xor'ed by the iterator must be equal to the string in **r12**, we can reverse it by xor'ing the **r12** string the same way.

    In [1]: "".join([chr(ord(c) ^ i) for i, c in enumerate('EQVxw6jaWd:oekw>~vMp$qsH)jE}isc')])                                                  
    Out[1]: 'EPT{s3lf_m0dify1ng_c0de_1s_fun}'


### Verifying the result

    echo -en "\x05EPT{s3lf_m0dify1ng_c0de_1s_fun}" | ./segFix
    Provide input:
    Input flag for verification:
    Wow, you entered the right flag, impressive!


## Flag

    EPT{s3lf_m0dify1ng_c0de_1s_fun}

