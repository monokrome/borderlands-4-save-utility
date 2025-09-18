import argparse
import sys
import yaml

from pathlib import Path

from bl4.crypto import decrypt_sav_to_yaml
from bl4.crypto import find_and_decode_serials_in_yaml
from bl4.crypto import extract_and_encode_serials_from_yaml
from bl4.crypto import encrypt_yaml_to_sav
from bl4.crypto import insert_decoded_items_in_yaml


def main():
    parser = argparse.ArgumentParser(
        prog="blcrypt",
        description=(
            "Encrypt/decrypt BL4 saves - decrypt to readable YAML, edit "
            "values, then encrypt.\nI'm not responsible for any damage you "
            "do your save file. Backup your save file before using this, and "
            "be smart."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dec = sub.add_parser(
        "decrypt",
        help="Decrypt a .sav to readable YAML.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    p_dec.add_argument(
        "-in",
        "--input",
        required=True,
        help="Path to input .sav",
    )

    p_dec.add_argument(
        "-out",
        "--output",
        help="Path to output .yaml (default: <input>.yaml)",
    )

    p_dec.add_argument(
        "-id", "--steamid", required=True, help="SteamID (e.g., 7656119...)"
    )

    p_dec.add_argument(
        "--decode-serials",
        action="store_true",
        help="Decode item serials and add editable stats section to YAML",
    )

    p_dec.epilog = (
        "Examples:\n"
        "  blcrypt decrypt -in 1.sav -out save.yaml -id 7656119XXXXXXXXX\n"
        "  blcrypt decrypt -in 1.sav -out save.yaml -id 7656119XXXXXXXXX "
        "--decode-serials\nIf PKCS7 or zlib errors appear, verify the "
        "SteamID is correct.\nUse --decode-serials to decode item stats "
        "for editing."
    )

    p_enc = sub.add_parser(
        "encrypt",
        help="Encrypt a YAML to .sav to be read by the game.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_enc.add_argument(
        "-in", "--input", required=True, help="Path to input .yaml"
    )
    p_enc.add_argument(
        "-out", "--output", help="Path to output .sav (default: <input>.sav)"
    )
    p_enc.add_argument(
        "-id",
        "--steamid",
        required=True,
        help="Steam ID (17 digits, starts with 7656119...)",
    )
    p_enc.add_argument(
        "--encode-serials",
        action="store_true",
        help="Encode modified item stats back to serials before encrypting",
    )

    p_enc.epilog = (
        "Examples:\n"
        "  blcrypt encrypt -in save.yaml -out 1.sav -id 7656119XXXXXXXXX\n"
        "  blcrypt encrypt -in save.yaml -out 1.sav -id 7656119XXXXXXXXX "
        "--encode-serials\nThe game should accept the .sav if the Steam ID "
        "matches the save owner.\nUse --encode-serials if you edited item "
        "stats and need them re-encoded."
    )

    args = parser.parse_args()

    try:
        if args.cmd == "decrypt":
            in_path = Path(args.input)
            out_path = (
                Path(args.output)
                if args.output
                else in_path.with_suffix(".yaml")
            )

            yaml_bytes = decrypt_sav_to_yaml(in_path, args.steamid)

            if args.decode_serials:
                yaml_data = yaml.safe_load(yaml_bytes.decode("utf-8"))
                decoded_serials = find_and_decode_serials_in_yaml(yaml_data)

                if decoded_serials:
                    yaml_data_with_decoded = insert_decoded_items_in_yaml(
                        yaml_data, decoded_serials
                    )
                    yaml_output = yaml.dump(
                        yaml_data_with_decoded,
                        default_flow_style=False,
                        allow_unicode=True,
                    )
                    out_path.write_text(yaml_output, encoding="utf-8")
                    print(
                        f"wrote {out_path} with {len(decoded_serials)} "
                        "decoded item serials"
                    )
                    print(
                        "Edit the '_DECODED_ITEMS' section to modify item "
                        "stats, then encrypt with --encode-serials"
                        "stats, then encrypt with --encode-serials"
                    )
                else:
                    yaml_output = yaml.dump(
                        yaml_data, default_flow_style=False, allow_unicode=True
                    )
                    out_path.write_text(yaml_output, encoding="utf-8")
                    print(
                        f"wrote {out_path} (no item serials found to decode)"
                    )
            else:
                out_path.write_bytes(yaml_bytes)
                print(f"wrote {out_path}")

        elif args.cmd == "encrypt":
            in_path = Path(args.input)
            out_path = (
                Path(args.output)
                if args.output
                else in_path.with_suffix(".sav")
            )

            if args.encode_serials:
                yaml_content = in_path.read_text(encoding="utf-8")
                yaml_data = yaml.safe_load(yaml_content)

                if "_DECODED_ITEMS" in yaml_data:
                    yaml_data_with_encoded = (
                        extract_and_encode_serials_from_yaml(yaml_data)
                    )
                    yaml_output = yaml.dump(
                        yaml_data_with_encoded,
                        default_flow_style=False,
                        allow_unicode=True,
                    )

                    temp_yaml = in_path.with_suffix(".temp.yaml")
                    temp_yaml.write_text(yaml_output, encoding="utf-8")
                    sav_bytes = encrypt_yaml_to_sav(temp_yaml, args.steamid)
                    temp_yaml.unlink()

                    out_path.write_bytes(sav_bytes)
                    print(f"wrote {out_path} with re-encoded item serials")
                else:
                    sav_bytes = encrypt_yaml_to_sav(in_path, args.steamid)
                    out_path.write_bytes(sav_bytes)
                    print(f"wrote {out_path} (no decoded items section found)")
            else:
                sav_bytes = encrypt_yaml_to_sav(in_path, args.steamid)
                out_path.write_bytes(sav_bytes)
                print(f"wrote {out_path}")

        else:
            parser.error("unknown command")
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
