#!/usr/bin/env python3
"""Check an ObenBlock payout address with the repository's reference codec.

    check_address.py <repo>/reference <address> mainnet|regtest

Exit 0 when the address is an ObenBlock single-key or policy address of the
network (obb1q / obb1m / obb1z on mainnet, obb1t / obb1n / tobb1z on
regtest); a GnB form is refused so the payout is never written in the old
family's notation. Python 3.9 or later, standard library only.
"""
import sys


def main(argv):
    if len(argv) != 4 or argv[3] not in ("mainnet", "regtest"):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 64
    ref, address, network = argv[1], argv[2].strip(), argv[3]
    sys.path.insert(0, ref)
    import obb_address  # noqa: E402  (the repository reference)

    want_prefix = ("obb1", "obb1z") if network == "mainnet" else ("obb1t", "obb1n", "tobb1z")
    if not address.lower().startswith(want_prefix) or (network == "mainnet" and address.lower().startswith(("obb1t", "obb1n"))):
        print(f"not an ObenBlock {network} address: {address}", file=sys.stderr)
        return 1
    try:
        net, kind, _payload, _form = obb_address.decode(address, "obenblock")
    except Exception as e:  # the reference raises AddressError (a ValueError)
        print(f"invalid address: {e}", file=sys.stderr)
        return 1
    if net != ("mainnet" if network == "mainnet" else "testnet"):
        print(f"address of the {net} slot, expected {network}", file=sys.stderr)
        return 1
    print(f"{address}: {network} {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
