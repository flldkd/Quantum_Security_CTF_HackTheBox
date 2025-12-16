from pwn import *
context(log_level="debug",os="linux")

io = process(['python', 'server.py'])

io.recvuntil(b"instructions : ")
io.sendline(b"H:0;CX:0,1;CX:0,3;H:2;CX:2,4")



io.interactive()
