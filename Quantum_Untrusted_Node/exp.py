from pwn import *
from util import xor
from hashlib import sha256
context(log_level="debug",os="linux")

#io = process(['python', 'server.py'])
io = remote('94.237.122.95',47889)
io.recvuntil(b"Sync signal: [")
sync_signal=io.recvuntil("]").replace(b']',b'')
print(sync_signal)
k_list = [int(x) for x in sync_signal.decode().strip().split(',')]
print(k_list)
measurement = b''
for k in k_list:
    # print(k)
    for i in range(k): 
        #print(i)
        if (i == 0 ):
            measurement+=b'0'
        elif (i == 1):
            measurement+=b'1'
        else:
            measurement+=b'-1'
        measurement+=b','
measurement = measurement.rstrip(b',')
m_list = [int(x) for x in measurement.decode().strip().split(',') if x]
print(measurement)
print(sum(k_list))
io.sendlineafter(b'measurement: ',measurement)

io.recvuntil(b"results: [")
node_results=io.recvuntil("]").replace(b']',b'')
print(node_results)
node_results_list = [x for x in node_results.decode().strip().split(',')]
print(node_results_list)
print(len(node_results_list))


io.recvuntil(b"gates: [")
recv_gates=io.recvuntil("]").replace(b']',b'')
print(recv_gates)
recv_gates_list = [int(x) for x in recv_gates.decode().strip().split(',')]
print(recv_gates_list)
print(len(recv_gates_list))
recv_gates_list_back=recv_gates_list
print(k_list)

send_gate_list=[]
times = 0
send_gate_str = ",".join(str(x) for x in recv_gates_list)

send_gate_str = send_gate_str.encode()
#print(send_gate_str)
io.sendlineafter(b"intercept receiver gates : ",send_gate_str)


io.recvuntil(b"Transmitter matches: [")
matches=io.recvuntil("]").replace(b']',b'')
print(matches)
matches_list = [x.strip() == 'True' for x in matches.decode().split(',')]
print(matches_list)
print(len(matches_list))


key=''
index = 0
result_index = 0
for k in k_list:
    gates_chunk = recv_gates_list[index : index + k]
    #measure_chunk = m_list[index : index + k]
    match_chunk = matches_list[index : index + k]
    result_chunk = node_results_list[result_index : result_index + 2]
    print(gates_chunk)
    print(match_chunk)
    print(result_chunk,'\n')
    for i in range(k):
        if (match_chunk[i]):
            if (gates_chunk[i] == 1):
                key += result_chunk[1]
            if (gates_chunk[i] == 0):
                key += result_chunk[0]
    index += k
    result_index += 2


key = key.replace('\'','').replace(' ','')
print(key)
print(len(key))
key = sha256(key.encode()).digest()
command = "TX|FETCH|SECRET"
command = xor(command.encode(),key).hex()
io.sendlineafter(b"Specify the data to send to receiver : ",command)
io.interactive()