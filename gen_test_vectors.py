# Check once 
import hmac
import hashlib
import random

# SHA-3 modes and their corresponding hash functions, digest lengths, and block sizes
# Mode: 0=224, 1=256, 2=384, 3=512
MODES = {
    0: (hashlib.sha3_224, 28, 144),
    1: (hashlib.sha3_256, 32, 136),
    2: (hashlib.sha3_384, 48, 104),
    3: (hashlib.sha3_512, 64, 72)
}

def generate_hmac_vectors(filename="vec_pd.txt", num_tests=20):
    """
    Generates test vectors for tb_hmac_sha3_pd.v
    Format:
    [number of tests]
    [mode] [key_length] [msg_length] [digest_length]
    [key bytes in hex...]
    [msg bytes in hex...]
    [mac bytes in hex...]
    """
    with open(filename, 'w') as f:
        f.write(f"{num_tests}\n") # Line 1: n (number of tests)
        for _ in range(num_tests):
            m = random.choice(list(MODES.keys()))
            hash_func, dl, block_size = MODES[m]

            # The testbench skips keys longer than the block size, so we constrain it here
            kl = random.randint(0, block_size)
            ml = random.randint(0, 200)

            key = bytes(random.getrandbits(8) for _ in range(kl))
            msg = bytes(random.getrandbits(8) for _ in range(ml))

            # Calculate expected HMAC
            mac = hmac.HMAC(key, msg, digestmod=hash_func).digest()

            # Write test header: m kl ml dl
            f.write(f"{m} {kl} {ml} {dl}\n")

            # Write data bytes (one per line for Verilog $fscanf compatibility)
            for b in key: f.write(f"{b:02x}\n")
            for b in msg: f.write(f"{b:02x}\n")
            for b in mac: f.write(f"{b:02x}\n")

def generate_sha3_vectors(filename="vec.txt", num_tests=20):
    """
    Generates test vectors for tb_sha3_pd.v
    Format:
    [number of tests]
    [mode] [msg_length] [digest_length]
    [msg bytes in hex...]
    [digest bytes in hex...]
    """
    with open(filename, 'w') as f:
        f.write(f"{num_tests}\n") # Line 1: n (number of tests)
        for _ in range(num_tests):
            m = random.choice(list(MODES.keys()))
            hash_func, dl, _ = MODES[m]

            ml = random.randint(0, 200)
            msg = bytes(random.getrandbits(8) for _ in range(ml))

            # Calculate expected SHA-3 digest
            digest = hash_func(msg).digest()

            # Write test header: m ml dl
            f.write(f"{m} {ml} {dl}\n")

            # Write data bytes
            for b in msg: f.write(f"{b:02x}\n")
            for b in digest: f.write(f"{b:02x}\n")

if __name__ == "__main__":
    generate_hmac_vectors("vec_pd.txt", 25)
    print("Generated vec_pd.txt for tb_hmac_sha3_pd")
    
    generate_sha3_vectors("vec.txt", 25)
    print("Generated vec.txt for tb_sha3_pd")
