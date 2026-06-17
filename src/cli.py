"""Interactive command-line interface."""

from src.rsa import (
    DEFAULT_KEY_BITS,
    decrypt_message,
    encrypt_message,
    generate_key_pair,
    get_max_message_block_size,
)


def show_menu() -> None:
    """Prints the main menu options."""
    print("\n # ======== RSAES-OAEP ======== # ")
    print("     [1] Generate RSA keys")
    print("     [2] Show keys")
    print("     [3] Encrypt message")
    print("     [4] Decrypt message")
    print("     [5] Exit")
    print(" # ---------------- ----------- # ")


def show_keys(public_key: tuple[int, int], private_key: tuple[int, int]) -> None:
    """Prints public and private keys."""
    print(f"                Public Key             : {public_key}")
    print(f"                Private Key            : {private_key}")


def show_rsa_values(
    p: int,
    q: int,
    n: int,
    totient: int,
    e: int,
    d: int,
) -> None:
    """Prints the main RSA values."""
    print(f"                Prime p                : {p}")
    print(f"                Prime q                : {q}")
    print(f"                Module (n)             : {n}")
    print(f"                Euler's Totient (φ(n)) : {totient}")
    print(f"                Public Exponent (e)    : {e}")
    print(f"                Private Exponent (d)   : {d}")


def menu() -> None:
    """Runs the interactive menu."""
    public_key = None
    private_key = None
    rsa_values = None

    while True:
        show_menu()
        option = input("     Option: ")
        print(" # ================ ========== # ")

        if option == "1":
            print("\n        ----- Generate RSA Keys ----- ")
            print(f"            Generating {DEFAULT_KEY_BITS}-bit RSA keys...")

            key_data = generate_key_pair(DEFAULT_KEY_BITS)
            public_key, private_key, p, q, n, totient, d = key_data
            _, e = public_key
            rsa_values = p, q, n, totient, e, d

            print("\n            -- RSA Values --")
            show_rsa_values(p, q, n, totient, e, d)
            print("\n            -- Generated Keys --")
            show_keys(public_key, private_key)

            block_size = get_max_message_block_size(public_key)
            print(f"                Max OAEP Block Size    : {block_size} bytes")

        elif option == "2":
            print("\n        ----- Show Keys -----")
            if public_key is None or private_key is None:
                print("            Generate RSA keys first.")
                continue

            if rsa_values is not None:
                p, q, n, totient, e, d = rsa_values
                print("\n            -- RSA Values --")
                show_rsa_values(p, q, n, totient, e, d)

            print("\n            -- Generated Keys --")
            show_keys(public_key, private_key)

        elif option == "3":
            print("\n        ----- Encrypt Message -----")
            if public_key is None:
                print("            Generate RSA keys first.")
                continue

            print("            This option receives text and returns")
            print("            RSAES-OAEP encrypted blocks.")
            print()

            message = input("                Message                 : ")
            encrypted_message = encrypt_message(message, public_key)

            if encrypted_message is None:
                print("                Could not encrypt message.")
                continue

            encrypted_blocks = []
            for encrypted_block in encrypted_message:
                encrypted_blocks.append(str(encrypted_block))

            encrypted_blocks_text = " ".join(encrypted_blocks)
            print(f"                Encrypted Blocks        : {encrypted_blocks_text}")

        elif option == "4":
            print("\n        ----- Decrypt Message -----")
            if private_key is None:
                print("            Generate RSA keys first.")
                continue

            print("            This option receives encrypted blocks separated")
            print("            by spaces and returns plain text.")
            print()

            encrypted_input = input("                Encrypted blocks        : ")
            encrypted_numbers = encrypted_input.split()
            numbers_are_valid = all(number.isdigit() for number in encrypted_numbers)

            if not encrypted_numbers or not numbers_are_valid:
                print("                Encrypted blocks must be separated by spaces.")
                continue

            encrypted_message = []
            for number in encrypted_numbers:
                encrypted_message.append(int(number))

            message = decrypt_message(encrypted_message, private_key)
            if message is None:
                print("                Could not decrypt message.")
                continue

            print(f"                Decrypted Message       : {message}")

        elif option == "5":
            print("            Goodbye.")
            break

        else:
            print("            Please choose a valid option.")
