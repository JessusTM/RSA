from src.rsa import (
    calculate_phi_n,
    decrypt_message,
    encrypt_message,
    generate_module,
    generate_private_exponent,
    generate_private_key,
    generate_public_exponent,
    generate_public_key,
    generate_random_primes,
    is_valid_message_for_ascii,
    is_valid_module_for_ascii,
)


# ------------ CLI UTILS ------------
def show_menu() -> None:
    """Prints the main menu options."""
    print("\n # ======== RSA with OAEP ======== # ")
    print("     [1] Generate RSA keys")
    print("     [2] Show keys")
    print("     [3] Encrypt message")
    print("     [4] Decrypt message")
    print("     [5] Exit")
    print(" # ---------------- -------------- # ")


def show_keys(public_key: tuple[int, int], private_key: tuple[int, int]) -> None:
    """Prints public and private keys."""
    print(f"                Public Key             : {public_key}")
    print(f"                Private Key            : {private_key}")


def show_rsa_values(n: int, phi_n: int, e: int, d: int) -> None:
    """Prints the main RSA values."""
    print(f"                Module (n)             : {n}")
    print(f"                Euler's Totient (φ(n)) : {phi_n}")
    print(f"                Public Exponent (e)    : {e}")
    print(f"                Private Exponent (d)   : {d}")


# ------------ MENU ------------
def menu() -> None:
    """Runs the interactive menu."""
    public_key = None
    private_key = None

    while True:
        show_menu()
        option = input("     Option: ")
        print(" # ================ ============== # ")

        if option == "1":
            while True:
                print("\n        ----- Generate RSA Keys ----- ")
                print("                [1] Random primes")
                print("                [2] Manual primes")
                print("                [3] Back")
                generation_option = input("            Option : ")
                print("        -------------- -------------- ")

                if generation_option == "1":
                    print("\n            -- Generated P and Q --")
                    p, q = generate_random_primes()
                    print(f"                Generated p            : {p}")
                    print(f"                Generated q            : {q}")

                elif generation_option == "2":
                    print("\n            -- Manual P and Q --")
                    p_input = input("                Prime number p         : ")
                    q_input = input("                Prime number q         : ")

                    if not p_input.isdigit() or not q_input.isdigit():
                        print("            Only numeric values are allowed.")
                        continue

                    p = int(p_input)
                    q = int(q_input)

                elif generation_option == "3":
                    break

                else:
                    print("            Please choose a valid option.")
                    continue

                n = generate_module(p, q)
                if n is None:
                    print("            p and q must be prime numbers.")
                    continue

                if not is_valid_module_for_ascii(n):
                    print(
                        "            p and q are too small. n must be greater than 127."
                    )
                    continue

                phi_n = calculate_phi_n(p, q)
                e = generate_public_exponent(phi_n)
                if e is None:
                    print("            Could not generate public exponent.")
                    continue

                d = generate_private_exponent(e, phi_n)
                if d is None:
                    print("            Could not generate private exponent.")
                    continue

                public_key = generate_public_key(n, e)
                private_key = generate_private_key(n, d)

                print("\n            -- RSA Values --")
                show_rsa_values(n, phi_n, e, d)
                print("\n            -- Generated Keys --")
                show_keys(public_key, private_key)
                break

        elif option == "2":
            print("\n        ----- Show Keys -----")
            if public_key is None or private_key is None:
                print("            Generate RSA keys first.")
                continue

            show_keys(public_key, private_key)

        elif option == "3":
            print("\n        ----- Encrypt Message -----")
            if public_key is None:
                print("            Generate RSA keys first.")
                continue

            print("            This option receives plain text and returns")
            print("            encrypted numbers.")
            print()

            message = input("                Message                 : ")
            if not is_valid_message_for_ascii(message):
                print("                Only standard ASCII characters are allowed.")
                continue

            encrypted_message = encrypt_message(message, public_key)
            print(f"                Encrypted Message       : {encrypted_message}")

        elif option == "4":
            print("\n        ----- Decrypt Message -----")
            if private_key is None:
                print("            Generate RSA keys first.")
                continue

            print("            This option receives encrypted numbers separated")
            print("            by spaces and returns plain text.")
            print()

            encrypted_input = input("                Encrypted numbers       : ")
            encrypted_numbers = encrypted_input.split()
            if not encrypted_numbers or not all(
                number.isdigit() for number in encrypted_numbers
            ):
                print("                Encrypted numbers must be separated by spaces.")
                continue

            encrypted_message = [int(number) for number in encrypted_numbers]
            message = decrypt_message(encrypted_message, private_key)
            print(f"                Decrypted Message       : {message}")

        elif option == "5":
            print("            Goodbye.")
            break

        else:
            print("            Please choose a valid option.")
