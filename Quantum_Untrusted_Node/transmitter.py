# =============================================================================
# Transmitter.py
# =============================================================================
# © Qubitrix™ Quantum Systems
# Proprietary Source Code – For internal use only
# Unauthorized copying, distribution, or reverse engineering is prohibited.
# =============================================================================
# Changelog
# -----------------------------------------------------------------------------
# v1.0.0 - Initial Release
#   - Implemented a basic quantum transmitter for key distribution.

# v1.1.0 - Current
#   - Preserve compatibility with previous version by mantaining legacy sync
#     signal transmission.
# -----------------------------------------------------------------------------

from qiskit import QuantumCircuit

import numpy as np

from util import xor, validate_entropy

from hashlib import sha256

class Transmitter:
    def __init__(self, bits = 128, λ = 2): 
        self.bits = bits
        self.λ = λ

    # 获取2倍bits长度的随机01，一半给key一半给gates
    def reset(self):
        random_bits = np.random.randint(2, size = 2 * self.bits)
        
        self.key    = random_bits[:self.bits]
        self.gates  = random_bits[self.bits:]

        self.sync_signal = None

    # 获取signal，用于确定k从而知道哪几个光子对应一个逻辑比特(self.bits)
    def get_sync_signal(self):
        return self.sync_signal
    
    # 生成电路
    def generate_circuits(self):
        self.reset()
        
        circuits = []
        k_values = []
        
        for i in range(self.bits):

            # np.random.poisson(self.λ)表示泊松分布期望事件发生次数为λ，+2表示至少为2
            k = np.random.poisson(self.λ) + 2

            # 对于一个逻辑比特(self.bits)，发出包含k个相同量子态光子的脉冲
            for _ in range(k):
                circuit = QuantumCircuit(1, 1)
                '''
                BB84协议:
                key=0,base=0(Z)-->|0>
                key=1,base=0(Z)-->|1>
                key=0,base=1(X)-->|+>
                key=1,base=1(X)-->|->
                '''
                if self.key[i] == 1:
                    circuit.x(0)
                
                if self.gates[i] == 1:
                    circuit.h(0)
                print(circuit.draw(output='text'))
                circuits.append(circuit)

            k_values.append(k)
        # 即为每个bits发射了k次的数组
        self.sync_signal = k_values

        return circuits

    def get_matches(self, gates: list[int]):
        if not self.sync_signal:
            print("Sync signal not generated yet.")
            return None

        tx_matches = []
        rx_matches = []
        
        idx = 0

        for i, k in enumerate(self.sync_signal):
            # 根据k，切片取出这一组对应的测量基
            gates_chunk = gates[idx : idx + k]
            
            match_index = None
            # 遍历这k个光子，如果输入的基和光子的基相等那就匹配成功，每组只选第一个匹配成功的
            for j, g in enumerate(gates_chunk):
                if g == self.gates[i]:
                    match_index = j
                    break
            # tx_matches存下k中第几个是符合的，没有就是none
            tx_matches.append(match_index)
            # k个中如果有匹配的光子就在rx_matches中加入true否则是false
            for j in range(k):
                if j == match_index:
                    rx_matches.append(True)
                else:
                    rx_matches.append(False)

            idx += k
        # 遍历self.key，如果对应的位置tx_matches是true就放入key
        key = ''.join([ str(bit) for bit, match in zip(self.key, tx_matches) if match is not None ])
        #print("selfgates",self.gates)
        #print('key',key,len(key))
        # 检查熵值
        if not validate_entropy(key):
            print("Insufficient entropy.")
            return None
        # 进行sha256哈希
        self.key = sha256(key.encode()).digest()

        return rx_matches

    def send_command(self, command: str):
        if not self.key:
            print("Transmitter key not generated yet.")
            return None
        # 对信息进行编码加密
        data = command.encode()
        
        return xor(data, self.key).hex()

    def process_command(self, data: str):
        if not self.key:
            print("Transmitter key not generated yet.")
            return None
        # 对信息进行编码解密
        data = bytes.fromhex(data)
        
        command = xor(data, self.key)

        if   command == b"RX|PING":          return "PONG"
        elif command == b"RX|FETCH|VERSION": return "v1.1.0"
        
        return None