from web3 import Web3
from web3.middleware import geth_poa_middleware
import os
import json
import time

challenge_id = int(input('The challenge you want to play (1 or 2 or 3): '))
assert challenge_id == 1 or challenge_id == 2 or challenge_id == 3

player_bytecode = bytes.fromhex(input('Player bytecode: '))

print('Launching anvil...')
os.system('anvil --silent --disable-console-log --ipc /dev/shm/eth.ipc &')
time.sleep(2)
w3 = Web3(Web3.IPCProvider('/dev/shm/eth.ipc'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
privatekey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' # anvil default private key
acct = w3.eth.account.from_key(privatekey)

print('Deploying challenge contract...')
bytecode, abi = json.load(open(f'contract{challenge_id}.json'))
Challenge = w3.eth.contract(abi=abi, bytecode=bytecode)
nonce = w3.eth.get_transaction_count(acct.address)
tx = Challenge.constructor().build_transaction({'nonce': nonce, 'from': acct.address})
signed_tx = w3.eth.account.sign_transaction(tx, private_key=privatekey)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
assert tx_receipt.status
print('Challenge contract address:', tx_receipt.contractAddress)
challenge = w3.eth.contract(address=tx_receipt.contractAddress, abi=abi)

print('Deploying player contract...')
recipients = []
for i in range(10):
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = {'to': None, 'data': player_bytecode, 'nonce': nonce, 'from': acct.address, 'gasPrice': w3.eth.gas_price, 'gas': 1000000}
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=privatekey)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if not tx_receipt.status:
        print('Failed deploying player contract')
        exit(-1)
    recipients.append(tx_receipt.contractAddress)

amounts = [w3.to_wei(1, 'ether')] * 10
nonce = w3.eth.get_transaction_count(acct.address)
tx = challenge.functions.batchTransfer(recipients, amounts).build_transaction({'nonce': nonce, 'from': acct.address, 'value': sum(amounts), 'gas': 1000000})
signed_tx = w3.eth.account.sign_transaction(tx, private_key=privatekey)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
if tx_receipt.status:
    print('Transfer success, no flag.')
    exit(-1)

print(open(f'flag{challenge_id}').read())
