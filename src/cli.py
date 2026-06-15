from src.rsa import (
    calculate_phi_n,
    decrypt_message,
    encrypt_message,
    generate_module,
    generate_private_exponent,
    generate_private_key,
    generate_public_exponent,
    generate_public_key,
    is_valid_message_for_ascii,
    is_valid_module_for_ascii,
)


# ------------ CLI UTILS ------------
def show_menu() -> None:
    """Prints the main menu options."""
    print("\n # ------ RSA with OAEP ------ # ")
    print("     [1] Generate RSA keys")
    print("     [2] Show keys")
    print("     [3] Encrypt message")
    print("     [4] Decrypt message")
    print("     [5] Exit")


def show_keys(public_key: tuple[int, int], private_key: tuple[int, int]) -> None:
    """Prints public and private keys."""
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")


def show_rsa_values(n: int, phi_n: int, e: int, d: int) -> None:
    """Prints the main RSA values."""
    print(f"n = {n}")
    print(f"φ(n) = {phi_n}")
    print(f"e = {e}")
    print(f"d = {d}")


# ------------ MENU ------------
def menu() -> None:
    """Runs the interactive menu."""
    public_key = None
    private_key = None

    while True:
        show_menu()
        option = input("Choose an option: ")

        if option == "1":
            p = int(input("Enter p: "))
            q = int(input("Enter q: "))

            n = generate_module(p, q)
            if n is None:
                print("p and q must be prime numbers.")
                continue

            if not is_valid_module_for_ascii(n):
                print("p and q are too small. n must be greater than 127.")
                continue

            phi_n = calculate_phi_n(p, q)
            e = generate_public_exponent(phi_n)
            if e is None:
                print("Could not generate public exponent.")
                continue

            d = generate_private_exponent(e, phi_n)
            if d is None:
                print("Could not generate private exponent.")
                continue

            public_key = generate_public_key(n, e)
            private_key = generate_private_key(n, d)

            show_rsa_values(n, phi_n, e, d)
            show_keys(public_key, private_key)

        elif option == "2":
            if public_key is None or private_key is None:
                print("Generate RSA keys first.")
                continue

            show_keys(public_key, private_key)

        elif option == "3":
            if public_key is None:
                print("Generate RSA keys first.")
                continue

            message = input("Enter message: ")
            if not is_valid_message_for_ascii(message):
                print("Only standard ASCII characters are allowed.")
                continue

            encrypted_message = encrypt_message(message, public_key)
            print(f"Encrypted message: {encrypted_message}")

        elif option == "4":
            if private_key is None:
                print("Generate RSA keys first.")
                continue

            encrypted_input = input("Enter encrypted numbers separated by spaces: ")
            encrypted_message = [int(number) for number in encrypted_input.split()]
            message = decrypt_message(encrypted_message, private_key)
            print(f"Decrypted message: {message}")

        elif option == "5":
            print("Goodbye.")
            break

        else:
            print("Invalid option.")
