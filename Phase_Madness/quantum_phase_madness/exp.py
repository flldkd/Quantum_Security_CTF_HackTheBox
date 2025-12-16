#!/usr/bin/env python
from pwn import *
import json
context(log_level="debug",os="linux")
#io = process(['python', 'server.py'])
io = remote("94.237.48.173",57929)
import math
#from sage.all import *
def calculate_rx_angle(measurement_results):
    count_0 = measurement_results.get("0", 0)
    count_1 = measurement_results.get("1", 0)
    total_shots = count_0 + count_1
    
    if total_shots == 0:
        return 0
    
    prob_1 = count_1 / total_shots
    
    half_theta_rad = math.asin(math.sqrt(prob_1))
    theta_deg = math.degrees(2 * half_theta_rad)
    
    return round(theta_deg)


def calculate_ry_angle(measurement_results):

    count_0 = measurement_results.get("0", 0)
    count_1 = measurement_results.get("1", 0)
    
    total_shots = count_0 + count_1
    if total_shots == 0:
        return 0
    
    prob_1 = count_1 / total_shots
    
    half_theta_rad = math.asin(math.sqrt(prob_1))
    theta_deg = math.degrees(2 * half_theta_rad)
    
    return round(theta_deg)


def calculate_rz_angle(measurement_results):

    count_0 = measurement_results.get("0", 0)
    count_1 = measurement_results.get("1", 0)
    total_shots = count_0 + count_1

    if total_shots == 0:
        return 0

    prob_0 = count_0 / total_shots

    half_theta_rad = math.acos(math.sqrt(max(0.0, min(1.0, prob_0))))

    theta_deg = math.degrees(2 * half_theta_rad)

    return round(theta_deg)
'''def test():
    i=0'''
flag=[]
'''0-36,36-72,72-结束'''
for i in range(72, 2000,3):
    io.recvuntil(b'to measure : ')
    io.sendline(str(i).encode())
    io.recvuntil(b"instructions : ")
    io.sendline(b'')
    mes=io.recvuntil(b"}")
    print(mes)
    data=calculate_rx_angle(json.loads(mes.decode('utf-8')))
    print(data)
    flag.append(data)
    bytes_obj = bytes(flag)
    flag_content = bytes_obj.decode('ascii')  # 或 'utf-8'
    print(repr(flag_content))
    io.recvuntil(b'to measure : ')
    io.sendline(str(i+1).encode())
    io.recvuntil(b"instructions : ")
    io.sendline(b'')
    mes=io.recvuntil(b"}")
    print(mes)
    data=calculate_ry_angle(json.loads(mes.decode('utf-8')))
    print(data)
    flag.append(data)
    bytes_obj = bytes(flag)
    flag_content = bytes_obj.decode('ascii')  # 或 'utf-8'
    print(repr(flag_content))
    io.recvuntil(b'to measure : ')
    io.sendline(str(i+2).encode())
    io.recvuntil(b"instructions : ")
    io.sendline(f"RZ:180,{i+2};RY:90,{i+2}")
    mes=io.recvuntil(b"}")
    print(mes)
    data=calculate_rz_angle(json.loads(mes.decode('utf-8')))
    print(data)
    flag.append(data)    
    print(flag)
    bytes_obj = bytes(flag)
    flag_content = bytes_obj.decode('ascii')  # 或 'utf-8'
    print(repr(flag_content))



'''if __name__ == "__main__":
    measurement_data = {"0": 43523, "1": 56477}
    angle_rad = calculate_rx_angle(measurement_data)
    print(angle_rad)
    measurement_data = {"0": 34632, "1": 65368}
    angle_rad = calculate_ry_angle(measurement_data)
    print(angle_rad)
    measurement_data = {"0": 39583, "1": 60417}
    angle = calculate_rx_angle(measurement_data)
    print(angle)'''
'''HTB{70_ph453_bru73f0rc1ng_0r_n07_70_ph453_bru73f0rc1ng...7h475_7h3_qu35710n...}'''