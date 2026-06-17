"""Interactive command-line interface."""

from src.rsa import (
    DEFAULT_KEY_BITS,
    decrypt_message,
    encrypt_message,
    generate_key_pair,
    get_max_message_block_size,
)

NUMBER_WIDTH = 80


def split_number_text(number: int, width: int = NUMBER_WIDTH) -> list[str]:
    """Splits a large number into fixed-width text chunks."""
    text = str(number)
    chunks = []

    for start in range(0, len(text), width):
        end = start + width
        chunks.append(text[start:end])

    return chunks


def print_large_value(label: str, value: int) -> None:
    """Prints a label and wraps large integer values."""
    chunks = split_number_text(value)
    print(f"                {label:<24}: {chunks[0]}")

    for chunk in chunks[1:]:
        print(f"                {'':<24}  {chunk}")


def print_wrapped_block(block: int) -> None:
    """Prints an encrypted block in copy-friendly wrapped lines."""
    for chunk in split_number_text(block):
        print(f"                {chunk}")


def parse_encrypted_blocks(encrypted_input: str) -> list[int] | None:
    """Parses encrypted blocks from one-line or wrapped pasted input."""
    if not encrypted_input.strip():
        return None

    if "|" in encrypted_input:
        raw_blocks = encrypted_input.split("|")
        encrypted_blocks = []

        for raw_block in raw_blocks:
            block = "".join(raw_block.split())
            if not block or not block.isdigit():
                return None

            encrypted_blocks.append(int(block))

        return encrypted_blocks

    encrypted_numbers = encrypted_input.split()
    if not encrypted_numbers:
        return None

    numbers_are_valid = all(number.isdigit() for number in encrypted_numbers)
    if not numbers_are_valid:
        return None

    # Wrapped output splits one ciphertext across short digit chunks. If every
    # chunk is at most NUMBER_WIDTH, rebuild it as one encrypted block.
    if len(encrypted_numbers) > 1 and all(
        len(number) <= NUMBER_WIDTH for number in encrypted_numbers
    ):
        return [int("".join(encrypted_numbers))]

    return [int(number) for number in encrypted_numbers]


def read_encrypted_blocks() -> list[int] | None:
    """Reads encrypted blocks until an empty line is entered."""
    print("                Encrypted blocks:")
    print("                Paste blocks, then press Enter on an empty line.")
    print("                Use '|' between wrapped blocks if there is more than one.")

    lines = []
    while True:
        line = input("                > ")
        if line == "":
            break

        lines.append(line)

    encrypted_input = "\n".join(lines)
    return parse_encrypted_blocks(encrypted_input)


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
    public_n, public_e = public_key
    private_n, private_d = private_key

    print("                Public Key:")
    print_large_value("n", public_n)
    print_large_value("e", public_e)
    print("                Private Key:")
    print_large_value("n", private_n)
    print_large_value("d", private_d)


def show_rsa_values(
    p: int,
    q: int,
    n: int,
    totient: int,
    e: int,
    d: int,
) -> None:
    """Prints the main RSA values."""
    print_large_value("Prime p", p)
    print_large_value("Prime q", q)
    print_large_value("Module (n)", n)
    print_large_value("Euler's Totient", totient)
    print_large_value("Public Exponent (e)", e)
    print_large_value("Private Exponent (d)", d)


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

            message = input("                Message                 : ")
            encrypted_message = encrypt_message(message, public_key)

            if encrypted_message is None:
                print("                Could not encrypt message.")
                continue

            print("                Encrypted Blocks:")
            for index, encrypted_block in enumerate(encrypted_message):
                if index > 0:
                    print("                |")

                print_wrapped_block(encrypted_block)

        elif option == "4":
            print("\n        ----- Decrypt Message -----")
            if private_key is None:
                print("            Generate RSA keys first.")
                continue

            encrypted_message = read_encrypted_blocks()
            if encrypted_message is None:
                print("                Invalid encrypted blocks.")
                continue

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
