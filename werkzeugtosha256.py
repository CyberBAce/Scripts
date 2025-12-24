import sys
import base64



def parse(text):
    try:
        prefix, alg, rest = text.split(":", 2)
        if prefix != "pbkdf2" or alg != "sha256":
            raise ValueError("Invalid Werkzeug (Flask) hash format")

        iters, salt, hash_val = rest.split("$", 2)
        iters = int(iters)
        if iters <= 0:
            raise ValueError("Iterations must be positive")

        return {
            "iterations": iters,
            "salt": salt,
            "hash": hash_val
        }

    except ValueError as e:
        return None, f"Error: {e}"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <werkzeug_hash>")
        sys.exit(1)

    text = sys.argv[1]
    result = parse(text)
    iter_variable = result["iterations"]
    salt = result["salt"]
    hash = result["hash"]
    salt_b64 = base64.b64encode(salt.encode()).decode()
    hash_b64 = base64.b64encode(hash.encode()).decode()    

    hashcat = f"sha256:{iter_variable}:{salt_b64}:{hash_b64}"
    print(hashcat)


if __name__ == "__main__":
    main()
