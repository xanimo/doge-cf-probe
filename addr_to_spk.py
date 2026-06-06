# addr_to_spk.py
import hashlib, base58

def addr_to_scriptpubkey(addr):
    decoded = base58.b58decode_check(addr)
    pubkey_hash = decoded[1:]  # strip version byte
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])

addr = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"  # example — swap for a real one
spk = addr_to_scriptpubkey(addr)
print(spk.hex())
