from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

from transmitter import Transmitter
from receiver import Receiver

FLAG = "flag{test}"
class TrustedNode:
    def __init__(self):
        self.backend = Aer.get_backend("qasm_simulator")

    def intercept_measure(self, gates: str, tx_circuits: list[QuantumCircuit]):
        if not gates:
            print("Zero qubits intercepted.")
            return tx_circuits, ""

        try:
            gates = [ int(gate) for gate in gates.split(",") ]
        except:
            print("Quantum gates must be specified as integers.")
            print("Example: 0,1,1,0,1")
            
            print("Note: 0 stands for a 'Z' measurement basis")
            print("      1 stands for a 'X' measurement basis")
            
            print("Zero qubits intercepted.")
            return tx_circuits, ""
        
        rx_circuits = []  # 发给bob的电路
        circuits    = []  # eve测量的电路
        for gate, circuit in zip(gates, tx_circuits):
            # 放行：把电路直接给rx电路
            if gate == -1:
                rx_circuits.append(circuit)
                continue
            #  拦截
            # 给bob的填入none--丢失
            rx_circuits.append(None)
            # 对这个光子进行测量，1为X基，0为Z基
            if gate == 1:
                circuit.h(0)

            circuit.measure(0, 0)
            
            circuits.append(circuit)

        compiled = transpile(circuits, self.backend)
        result = self.backend.run(compiled, shots = 1, memory = True).result()
        
        results = [result.get_memory(i)[0] for i in range(len(compiled))]

        return rx_circuits, results

    def intercept_gates(self, gates: str):
        if not gates:
            print("Zero receiver gates intercepted.")
            return None

        try:
            gates = [ int(gate) for gate in gates.split(",") ]
        except:
            print("Quantum gates must be specified as integers.")
            print("Zero receiver gates intercepted.")
            return None
        
        return gates

def main():
    print("""
        Operator, Knox here.
        I designed a simple terminal to interact with the compromised Trusted Node
        and the quantum communication.
        You know what to do, over.
    """)

    tx = Transmitter()  #alice
    rx = Receiver() #bob

    tn = TrustedNode() #eve

    circuits = tx.generate_circuits()# alice随机生成密钥和测量基
    print(f"Sync signal: {tx.get_sync_signal()}")# 获取k的情况即为signal

    tn_gates = input("Specify the gates to intercept receiver's measurement: ")
    rx_circuits, tn_results = tn.intercept_measure(tn_gates, circuits)# 获取拦截下来的测量结果和给bob的电路
    
    # 显示eve拦截测量的数据
    if len(tn_results) != 0:
        print(f"Trusted Node results: {tn_results}")# 显示拦截的测量结果

    rx_gates = rx.measure(rx_circuits)

    if rx_gates is None:
        print("Closing connection.")
        return
    
    print(f"Receiver gates: {rx_gates.tolist()}")# bob公开他的基

    tn_gates = input("Specify the gates to intercept receiver gates : ")
    tn_gates = tn.intercept_gates(tn_gates)

    if tn_gates is None:
        tn_gates = rx_gates
    
    rx_matches = tx.get_matches(tn_gates)# alice 计算哪些位保留

    if rx_matches is None:
        print("Closing connection.")
        return

    print(f"Transmitter matches: {rx_matches}")

    rx.filter(rx_matches)# bob生成最终密钥

    # 验证密钥
    if tx.key != rx.key:
        print("Keys do not match. Closing connection.")
        return

    while True:
        data = input("Specify the data to send to receiver : ")
        command = rx.process_command(data)# 输入加密后的指令

        if command is not None:
            print(f"Command: {command}")
        else:
            print("Command not received.")

if __name__ == "__main__":
    main()