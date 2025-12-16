from pwn import *
context(log_level="debug",os="linux")

io = process(['python', 'server.py'])
#io = remote("83.136.251.67",56224)
bits_str = b""

'''io.recvuntil(b'bitpairs')
init=io.recvuntil(b']')
io.success(init)'''

io.recvuntil(b"Qubit 1/")
num=int(io.recv(2))
print("num",num)
for i in range(num):
    io.recvuntil(b"Basis : ")
    basic=io.recv(1)
    print(basic)
    io.recvuntil(b"Measurement of qubit 0 : ")
    q0=io.recv(1)
    print(q0)
    io.recvuntil(b"Measurement of qubit 1 : ")
    q1=io.recv(1)
    print(q1)
    if(basic==b"Z"):
        if(q0==b"0"):
            if(q1==b"0"):
                io.recvuntil(b"instructions :")
                io.sendline(b"X:1")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("Z")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"0"):
                    bits_str+=b"00"
                if(q2==b"1"):
                    bits_str+=b"01"
            if(q1==b"1"):
                io.recvuntil(b"instructions :")
                io.sendline(b"X:1")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("Z")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"1"):
                    bits_str+=b"00"
                if(q2==b"0"):
                    bits_str+=b"01"
        if(q0==b"1"):
            if(q1==b"0"):
                io.recvuntil(b"instructions :")
                io.sendline(b"X:1")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("Z")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"0"):
                    bits_str+=b"00"
                if(q2==b"1"):
                    bits_str+=b"01"
            if(q1==b"1"):
                io.recvuntil(b"instructions :")
                io.sendline(b"X:1")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("Z")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"1"):
                    bits_str+=b"00"
                if(q2==b"0"):
                    bits_str+=b"01"
    if(basic==b"X"):
        if(q0==b"0"):
            if(q1==b"0"):
                io.recvuntil(b"instructions :")
                io.sendline(b"H:2;H:2")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("X")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"0"):
                    bits_str+=b"10"
                if(q2==b"1"):
                    bits_str+=b"11"
            if(q1==b"1"):
                io.recvuntil(b"instructions :")
                io.sendline(b"H:2;H:2")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("X")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"1"):
                    bits_str+=b"11"
                if(q2==b"0"):
                    bits_str+=b"10"
        if(q0==b"1"):
            if(q1==b"0"):
                io.recvuntil(b"instructions :")
                io.sendline(b"H:2;H:2")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("X")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"0"):
                    bits_str+=b"11"
                if(q2==b"1"):
                    bits_str+=b"10"
            if(q1==b"1"):
                io.recvuntil(b"instructions :")
                io.sendline(b"H:2;H:2")
                io.recvuntil("Specify the measurement basis :")
                io.sendline("X")
                io.recvuntil("Measurement of qubit 2 : ")
                q2=io.recv(1)
                print("q2",q2)
                if(q2==b"1"):
                    bits_str+=b"10"
                if(q2==b"0"):
                    bits_str+=b"11"
    print("bit_str",bits_str)

binary_string = bits_str.decode('ascii')

bytes_list = [binary_string[i: i + 8] for i in range(0, len(binary_string), 8)]


chars = [chr(int(byte, 2)) for byte in bytes_list]

result_string = ''.join(chars)

print("转换后的字符串:", result_string)

io.interactive()