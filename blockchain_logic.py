import time
import hashlib
import json
import requests
from urllib.parse import urlparse

# Blockchain Class
class Blockchain:

    def __init__(self):
        self.chain = []
        self.create_block(proof=1, previous_hash='0', sender='N.A', receiver='N.A', file_hash='N.A')
        self.nodes = set()
        
        # Adding multiple nodes for better fault tolerance
        self.nodes.add("https://blue-lock-1.onrender.com")
        self.nodes.add("https://blue-lock-2.onrender.com")
        self.nodes.add("https://blue-lock-3.onrender.com")

    def create_block(self, proof, previous_hash, sender, receiver, file_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(time.strftime("%d %B %Y , %I:%M:%S %p", time.localtime())),
            'proof': proof,
            'previous_hash': previous_hash,
            'sender': sender,
            'receiver': receiver,
            'shared_files': file_hash
        }
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]

            # Validate previous hash
            if block['previous_hash'] != self.hash(previous_block):
                return False

            # Validate proof of work
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False

            previous_block = block
            block_index += 1

        return True

    def add_file(self, sender, receiver, file_hash):
        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        
        new_block = self.create_block(proof, previous_hash, sender, receiver, file_hash)
        
        print(f"DEBUG: New Block Added -> {new_block}")  # Debugging Info
        return new_block

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)

        for node in network:
            try:
                response = requests.get(f'{node}/get_chain', timeout=5)  # Timeout prevents long waits
                if response.status_code == 200:
                    length = response.json().get('length')
                    chain = response.json().get('chain')
                    if length and length > max_length and self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
            except requests.RequestException as e:
                print(f"WARNING: Could not connect to {node}. Skipping... Error: {e}")

        if longest_chain:
            self.chain = longest_chain
            return True
        return False

# ✅ Creating an instance of Blockchain to be used in server.py
blockchain = Blockchain()
