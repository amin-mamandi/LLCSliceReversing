import os
import slice_functions



def print_chains(raw_chains):
    for idx, chain in enumerate(raw_chains):
        print(f"[+] chain {idx}: {chain}")


def extend_to_15(function, output_bit, raw_chains, start_bit):
    """
    Extends the given chains to 15 bits starting from the specified start bit.

    Args:
        function (object): The target slice function.
        output_bit (int): The target output bit of the slice function.
        raw_chains (list of lists): A list of chains where each chain is a list of bits.
        start_bit (int): The bit position from which to start the extension.
    """
    print(f"[*] Extending to 15 starting from {start_bit}")
    pattern = slice_functions.read_pattern(f"pattern_lab73/pattern_00.txt")
    for bit in range(start_bit, 16):
        # Find extensions of the chains that satisfy the pattern
        res = function.extend_bit(pattern, output_bit, bit, bit, raw_chains)
        # Check if the extension was successful
        if len(res) == 0:
            print(f"[-] Failed at {bit}: No candidates")
            break
        elif len(res) > 1:
            print(f"[-] Failed at {bit}: Multiple candidates")
            break
        x = res[0]
        # Append the new bit to the chains
        for idx, append in enumerate(x):
            if append == 1:
                raw_chains[idx].append(bit)
    # Print the chains
    print_chains(raw_chains)
    # Verify the correctness of the extension
    function.verify_bit(pattern, output_bit, True)
    print()


def extend_upper_bits(function, output_bit, raw_chains, upper_bound):
    """
    Extends the given chains for a function up to a specified upper bound.

    Args:
        function (object): The traget slice function.
        output_bit (int): The target output bit of the slice function.
        raw_chains (list): A list of raw chains to be extended.
        upper_bound (int): The upper bound up to which the bits should be extended.
    """
    print(f"[*] Extending upper bits up to {upper_bound}")
    for bit in range(16, upper_bound + 1):
        pattern = slice_functions.read_pattern(f"pattern_lab73/pattern_{bit}.txt")
        valid_pattern = [(addr, slc) for addr, slc in pattern if slc >= 0]
        invalid = len(pattern) - len(valid_pattern)

        if invalid > 0:
            print(
                f"[!] bit {bit}: skipping invalid labels ({invalid}/{len(pattern)} are -1)"
            )

        # If the remaining labeled data is too small, skip this bit.
        if len(valid_pattern) < 64:
            print(f"[!] bit {bit}: skipped (only {len(valid_pattern)} valid samples)")
            continue

        res = function.extend_bit(valid_pattern, output_bit, bit, 15, raw_chains)
        if len(res) == 0:
            print(f"[-] Failed at {bit}: No candidates")
            break
        elif len(res) > 1:
            print(f"[-] Failed at {bit}: Multiple candidates")
            break
        x = res[0]
        for idx, append in enumerate(x):
            if append == 1:
                raw_chains[idx].append(bit)
    print_chains(raw_chains)
    print()


def dummy(x):
    return 0


def or2(x, y):
    return x | y


def and2(x, y):
    return x & y 


def detect_num_slices(pattern):
    max_slice = max(slice_idx for _, slice_idx in pattern)
    return max_slice + 1


def build_10_slice_config():
    # Bit 0 is linear for 10-slice on SPR
    l6b = slice_functions.XorChain(
        [6, 8, 9, 10, 14, 15, 17, 18, 20, 23, 27, 30, 31, 34, 36, 38]
    ).evaluate

    # Raw chains found for the mixer's MSB in the base region.
    chain_0_raw = [7]
    chain_1_raw = [9]
    chain_2_raw = [10]
    chain_3_raw = [11]
    raw_chains = [chain_0_raw, chain_1_raw, chain_2_raw, chain_3_raw]

    chain_0 = slice_functions.XorChain(chain_0_raw).evaluate
    chain_1 = slice_functions.XorChain(chain_1_raw).evaluate
    chain_2 = slice_functions.XorChain(chain_2_raw).evaluate
    chain_3 = slice_functions.XorChain(chain_3_raw).evaluate

    # python3 rev_mixer.py -n 11 -i 3 --optimize -f pattern_lab73/pattern_00.txt
    # Output (Synthesized logic):
    #     x6 = and2(x1, x3)
    #     x7 = or2 (x4, x5)
    #     y0 = and2(x6, x7)
    # with x0, . . . ,x5 mapped to address bits b6, . . . ,b11

    # bit3 = b7 & b9 & (b10 | b11) for the base range.
    def bit_3(x):
        x0 = chain_0(x)
        x1 = chain_1(x)
        x2 = chain_2(x)
        x3 = chain_3(x)
        return and2(and2(x0, x1), or2(x2, x3))

    # Only bit0 and bit3 are relevant here
    slice_function = slice_functions.SliceFunction([l6b, dummy, dummy, bit_3])

    return {
        "slice_function": slice_function,
        "output_bit": 3,
        "raw_chains": raw_chains,
        "start_bit": 12,
    }


def build_20_slice_config():
    # Linear chains for the least significant 2 bits.
    l6b = slice_functions.XorChain(
        [6, 8, 9, 10, 14, 15, 17, 18, 20, 23, 27, 30, 31, 34, 36, 38]
    ).evaluate
    l6f = slice_functions.XorChain(
        [6, 7, 8, 12, 16, 17, 20, 21, 22, 23, 24, 25, 26, 28, 30, 33, 35]
    ).evaluate

    # Define the chains
    chain_0_raw = [7]
    chain_1_raw = [9]
    chain_2_raw = [10]
    chain_3_raw = [11]
    raw_chains = [chain_0_raw, chain_1_raw, chain_2_raw, chain_3_raw]

    chain_0 = slice_functions.XorChain(chain_0_raw).evaluate
    chain_1 = slice_functions.XorChain(chain_1_raw).evaluate
    chain_2 = slice_functions.XorChain(chain_2_raw).evaluate
    chain_3 = slice_functions.XorChain(chain_3_raw).evaluate

    # Define the mixer circuit for the least significant bit
    def bit_4(x):
        # Define the chains
        x0 = chain_0(x)
        x1 = chain_1(x)
        x2 = chain_2(x)
        x3 = chain_3(x)
        # ++++ Insert your logic here ++++
        x4 = or2(x2, x3)
        x5 = and2(x1, x4)
        y0 = and2(x0, x5)
        # ++++++ End of your logic +++++++
        return y0

    slice_function = slice_functions.SliceFunction([l6b, l6f, dummy, dummy, bit_4])

    return {
        "slice_function": slice_function,
        "output_bit": 4,
        "raw_chains": raw_chains,
        "start_bit": 12,
    }


def main():
    """
    Reverse engineer upper bits of mixer input chains.
    Automatically selects a supported config based on pattern_00.txt.
    """
    pattern_00 = os.path.join("pattern_lab73", "pattern_00.txt")
    pattern = slice_functions.read_pattern(pattern_00)
    num_slices = detect_num_slices(pattern)

    if num_slices == 10:
        cfg = build_10_slice_config()
    elif num_slices == 20:
        cfg = build_20_slice_config()
    else:
        raise ValueError(
            f"Unsupported slice count {num_slices}. Only 10 and 20 are implemented."
        )

    print(f"[+] Auto-detected {num_slices} slices from {pattern_00}")
    output_bit = cfg["output_bit"]
    raw_chains = cfg["raw_chains"]
    slice_function = cfg["slice_function"]
    start_bit = cfg["start_bit"]
    print(f"[+] Using output bit {output_bit} with {len(raw_chains)} base chains")

    # Extend the chains to 15 bits
    extend_to_15(slice_function, output_bit, raw_chains, start_bit)
    # Extend the chains up to bit 36
    extend_upper_bits(slice_function, output_bit, raw_chains, 36)


if __name__ == "__main__":
    main()
