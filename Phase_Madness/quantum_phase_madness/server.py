from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from math import pi
import json

class PhaseEncoder:
    def __init__(self, data: bytes):
        for i in range(0, len(data)):
            print(data[i])
        self.base_circuit = QuantumCircuit(len(data), 1)

        for i in range(0, len(data), 3):
            self.base_circuit.rx(self.degrees_to_radians(data[i]), i)

            if i + 1 < len(data):
                self.base_circuit.ry(self.degrees_to_radians(data[i + 1]), i + 1)

            if i + 2 < len(data):
                self.base_circuit.h(i + 2)
                self.base_circuit.rz(self.degrees_to_radians(data[i + 2]), i + 2)

        print(self.base_circuit.draw())

        self.backend = Aer.get_backend("qasm_simulator")
        self.backend.set_max_qubits(len(data))

    '''
       ┌────────────┐             
 q_0: ─┤ Rx(1.7802) ├─────────────
       └┬──────────┬┘             
 q_1: ──┤ Ry(3π/5) ├──────────────
        └──┬───┬───┘ ┌───────────┐
 q_2: ─────┤ H ├─────┤ Rz(1.693) ├
       ┌───┴───┴────┐└───────────┘
 q_3: ─┤ Rx(1.7977) ├─────────────
       ├────────────┤             
 q_4: ─┤ Ry(2.1468) ├─────────────
       └───┬───┬────┘┌───────────┐
 q_5: ─────┤ H ├─────┤ Rz(1.693) ├
       ┌───┴───┴───┐ └───────────┘
 q_6: ─┤ Rx(1.693) ├──────────────
       ├───────────┤              
 q_7: ─┤ Ry(1.693) ├──────────────
       └───┬───┬───┘ ┌───────────┐
 q_8: ─────┤ H ├─────┤ Rz(1.693) ├
       ┌───┴───┴────┐└───────────┘
 q_9: ─┤ Rx(2.1817) ├─────────────
      ┌┴────────────┤             
q_10: ┤ Ry(0.22689) ├─────────────
      └────┬───┬────┘ ┌──────────┐
q_11: ─────┤ H ├──────┤ Rz(π/18) ├
           └───┘      └──────────┘
 c: 1/════════════════════════════

    '''

    def degrees_to_radians(self, degrees: int):
        return degrees * (pi / 180)

    def measure(self, circuit: QuantumCircuit, qubit: int):
        circuit.measure(qubit, 0)
        
        compiled = transpile(circuit, self.backend)
        results = self.backend.run(compiled, shots = 100_000).result()
        
        return results.get_counts()
    
    def complete_circuit_and_measure(self, qubit: int, instructions: str):
        if qubit >= self.base_circuit.num_qubits:
            print(f"Index {qubit} out of range for size {self.base_circuit.num_qubits}")
            return None

        if len(instructions) == 0:#如果没有其他门操作，可以直接测量
            return self.measure(self.base_circuit, qubit)

        circuit = self.base_circuit.copy()
        
        instructions = instructions.split(";")
        for instr in instructions:
            parts = instr.split(":")

            if len(parts) != 2:
                print(f"Invalid instruction: {instr}. Expected format: <gate>:<params>")
                print("Examples: H:<target> | RX:<phase>,<target>")
                return None

            gate, params = parts

            try:
                params = [ int(p) for p in params.split(",") ]
            except:
                print("Quantum gate input parameters must be integers.") 
                print("Examples: H:0 | RX:90,1")
                return None

            if len(params) == 2:
                if params[1] >= self.base_circuit.num_qubits:
                    print(f"Qubit indexes must be less than {self.base_circuit.num_qubits}")
                    return None

                phase = self.degrees_to_radians(params[0])
                if   gate == "RX": circuit.rx(phase, params[1])
                elif gate == "RY": circuit.ry(phase, params[1])
                elif gate == "RZ": circuit.rz(phase, params[1])
                else:
                    print(f"Quantum gate '{gate}' is invalid or unexpected with 2 parameters.")
                    return None

            else:
                print(f"Unsupported number of parameters ({len(params)}) for quantum gate '{gate}'.")
                return None

        return self.measure(circuit, qubit)

def main():
    encoder = PhaseEncoder(open('flag.txt', 'rb').read())

    while True:
        qubit = input('Specify the qubit index you want to measure : ')
        try:
            qubit = int(qubit)
        except:
            print('The qubit index must be an integer.')
            continue

        instructions = input('Specify the instructions : ')
        
        results = encoder.complete_circuit_and_measure(qubit, instructions)

        if results is None:
            continue

        print(json.dumps(results))

if __name__ == '__main__':
    main()