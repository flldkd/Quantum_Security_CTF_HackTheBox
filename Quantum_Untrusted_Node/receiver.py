# =============================================================================
# Receiver.py
# =============================================================================
# © Qubitrix™ Quantum Systems
# Proprietary Source Code – For internal use only
# Unauthorized copying, distribution, or reverse engineering is prohibited.
# =============================================================================
# Changelog
# -----------------------------------------------------------------------------
# v1.0.0 - Initial Release
#   - Implemented a basic quantum receiver for key distribution.

# v1.1.0 - Current
#   - Removed internal sync signal handling.
#   - Consider 'None' value quantum circuit as a lost qubit for error
#     handling in further versions.
# -----------------------------------------------------------------------------

from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

from util import validate_entropy, xor
from secret import FLAG

import numpy as np
from hashlib import sha256

class Receiver:
    def __init__(self, bits = 128):
        self.backend = Aer.get_backend("qasm_simulator")
        self.bits = bits

    def reset(self):
        self.results = None
        self.key = None

    def measure(self, circuits: list[QuantumCircuit]):
        self.reset()

        if all(circuit is None for circuit in circuits):
            print("Zero qubits to measure.")
            return None
        # 生成一个数组，随机赋值为0或1
        gates = np.random.randint(2, size = len(circuits))
        #print("circuits",circuits)
        #print("this is:",gates)

        valid_circuits = []
        
        results = [None] * len(circuits)
        
        for i in range(len(circuits)):
            if circuits[i] is None:
                gates[i] = -1
                continue
            # 如果gate为1就给个h门再测量（X基），否则直接测量（Z基）
            if gates[i] == 1:
                circuits[i].h(0)
            circuits[i].measure(0, 0)

            valid_circuits.append(circuits[i])

        compiled = transpile(valid_circuits, self.backend)
        result = self.backend.run(compiled, shots = 1, memory = True).result()
        
        _results = [result.get_memory(i)[0] for i in range(len(compiled))]

        # 因为刚才把none跳过了，所以现在拿到的_result列表有可能比原始circuits短，所以要对准回原先的位置
        for i in range(len(circuits)):
            # 如果none填回也跳过
            if circuits[i] is None:
                continue
            # 每次把顶部填入
            results[i] = _results.pop(0)
        
        self.results = results
        
        return gates
# 关键
    def filter(self, matches: list[bool]):
        # join是把留下的拼在一起，match是个布尔表
        key = ''.join([ result for result, match in zip(self.results, matches) if match ])
        # 熵值检查
        if not validate_entropy(key):
            print("Insufficient entropy.")
            return None
        
        self.key = sha256(key.encode()).digest()

    def send_command(self, command: str):
        if not self.key:
            print("Receiver key not generated yet.")
            return None
        # 对command编码
        data = command.encode()
        # 加密：xor内容和密钥
        return xor(data, self.key).hex()

    def process_command(self, data: str):
        #print('command',data)
        if not self.key:
            print("Receiver key not generated yet.")
            return None
        # 解码data
        #print('command',data)
        data = bytes.fromhex(data)
        #print('command',data)
        # 解密
        command = xor(data, self.key)
        #print('command',command)
        # 获取flag的条件
        if   command == b"TX|PING":          return "PONG"
        elif command == b"TX|FETCH|VERSION": return "v1.1.0"
        elif command == b"TX|FETCH|SECRET":  return FLAG
            
        return None