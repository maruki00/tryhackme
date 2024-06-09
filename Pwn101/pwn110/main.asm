;extern puts
;extern exit
;
;section .data
;	msg db "hello world",0x0a,0x00
;section .text
;global main
;main:
;	mov rcx,msg
;	call puts
;
;
;	mov rdi,0
;	call exit


section .data
    hello db 'Hello, World!', 0

section .text
    extern puts
    extern ExitProcess

    global main

main:
    ; Put the address of the string in rcx (first argument to puts)
    mov rcx, hello
    ; Call the puts function
    call puts

    ; Exit the program
    mov ecx, 0       ; status 0
    call ExitProcess
