# Quantum Security CTF Writeups
README是我用ai生成的，exp.py是我写的对应题目的wp。

This repository contains my solutions and writeups for a series of Quantum Security CTF challenges. These challenges cover various aspects of quantum computing security, including quantum teleportation, Quantum Key Distribution (QKD), quantum circuit manipulation, and phase encoding.

## Challenge List

### 1. Flagportation
- **Category**: Quantum Teleportation
- **Library**: Qutip
- **Description**: Simulates a quantum teleportation system. The flag is encoded into a quantum state, and players must construct a specific sequence of quantum gate operations to correctly measure and recover the flag.
- **Path**: `Flagportation/`

### 2. Global Hyperlink Zone
- **Category**: Quantum Entanglement / Circuit Construction
- **Library**: Qiskit
- **Description**: A challenge involving the prototype of a "Global Hyperlink". Players need to provide instructions to build a quantum circuit that generates a quantum state satisfying specific entanglement correlation patterns (Hyperlink connection pattern).
- **Path**: `Global_Hyperlink_Zone/`

### 3. Phase Madness
- **Category**: Phase Encoding / State Tomography
- **Library**: Qiskit
- **Description**: The flag is encoded in the phases of qubits. Players must extract the phase information by applying quantum gates and performing measurements to restore the flag.
- **Path**: `Phase_Madness/`

### 4. QLotto
- **Category**: Quantum Random Number Generation (QRNG) / Prediction
- **Library**: Qiskit
- **Description**: A quantum lottery game. The system uses a quantum circuit to generate random numbers. Players need to manipulate or predict the lottery results by injecting specific quantum gate operations to win the Jackpot.
- **Path**: `QLotto/`

### 5. Quantum Untrusted Node
- **Category**: QKD / Man-in-the-Middle Attack
- **Library**: Qiskit
- **Description**: Simulates a compromised Quantum Key Distribution (QKD) node. The player acts as a Man-in-the-Middle (Eve), intercepting and resending quantum states and tampering with measurement basis information to steal the shared key without Alice and Bob noticing.
- **Path**: `Quantum_Untrusted_Node/`

## Environment & Usage

This project relies mainly on Python and the following quantum computing libraries:
- `qiskit`
- `qiskit-aer`
- `qutip`
- `numpy`, `scipy`

### Installation
It is recommended to use a Python virtual environment:

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

Install the necessary libraries:
```bash
pip install qiskit qiskit-aer qutip numpy scipy
```

### How to Run
Each challenge directory contains the server simulation script (usually `server.py`) and the solution script (e.g., `exp.py`).

Taking `Quantum_Untrusted_Node` as an example:
1. Navigate to the challenge directory:
   ```bash
   cd Quantum_Untrusted_Node
   ```
2. Run the solution script (ensure `server.py` is in the same directory or correctly referenced):
   ```bash
   python exp.py
   ```

*(Note: Some challenges may require running from specific subdirectories; please refer to the file structure.)*

## Disclaimer
The code in this repository is for CTF educational and exchange purposes only.
