import os
import numpy as np
import pyopencl as cl

DEFAULT_INPUT = "SerialKeys.txt"
DEFAULT_OUTPUT = "external_data.h"
ID_BITS = 64
CHUNK_SIZE = 120
ENTRIES_PER_LINE = 3

def escape_wide_literal(s):
    return s.replace("\\", "\\\\").replace("\"", "\\\"")

def split_into_chunks(s, chunk_size):
    return [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]

def fnv1a_opencl(serials_bytes):
    ctx = cl.create_some_context()
    queue = cl.CommandQueue(ctx)

    kernel_src = """
    __kernel void fnv1a(
        __global const uchar *data,
        __global const int *offsets,
        __global const int *lengths,
        __global ulong *hashes)
    {
        int gid = get_global_id(0);
        ulong h = 14695981039346656037UL;
        int start = offsets[gid];
        int len = lengths[gid];
        for (int i = 0; i < len; i++) {
            h ^= (ulong)data[start + i];
            h *= 1099511628211UL;
        }
        hashes[gid] = h;
    }
    """
    program = cl.Program(ctx, kernel_src).build()

    total_bytes = sum(len(b) for b in serials_bytes)
    data_flat = np.zeros(total_bytes, dtype=np.uint8)
    offsets = np.zeros(len(serials_bytes), dtype=np.int32)
    lengths = np.zeros(len(serials_bytes), dtype=np.int32)

    offset = 0
    for i, b in enumerate(serials_bytes):
        data_flat[offset:offset+len(b)] = np.frombuffer(b, dtype=np.uint8)
        offsets[i] = offset
        lengths[i] = len(b)
        offset += len(b)

    mf = cl.mem_flags
    data_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data_flat)
    offsets_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=offsets)
    lengths_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=lengths)
    hashes_buf = cl.Buffer(ctx, mf.WRITE_ONLY, size=len(serials_bytes) * 8)

    program.fnv1a(queue, (len(serials_bytes),), None, data_buf, offsets_buf, lengths_buf, hashes_buf)

    hashes = np.zeros(len(serials_bytes), dtype=np.uint64)
    cl.enqueue_copy(queue, hashes, hashes_buf)
    queue.finish()
    return hashes

def main():
    input_file = input(f"Enter input file [{DEFAULT_INPUT}]: ").strip() or DEFAULT_INPUT
    output_file = input(f"Enter output file [{DEFAULT_OUTPUT}]: ").strip() or DEFAULT_OUTPUT

    if not os.path.exists(input_file):
        print(f"{input_file} not found.")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        serials = [line.strip() for line in f if line.strip()]

    rng = np.random.default_rng()
    used_ids = set()
    entries = []

    serials_bytes = [s.encode("utf-8") for s in serials]
    hashes = fnv1a_opencl(serials_bytes)

    for i, s in enumerate(serials):
        while True:
            rand_id = rng.integers(0, 2**ID_BITS, dtype=np.uint64)
            if rand_id not in used_ids:
                used_ids.add(rand_id)
                break

        hash_val = hashes[i]
        escaped = escape_wide_literal(s)
        chunks = split_into_chunks(escaped, CHUNK_SIZE)
        literal = " \\\n        ".join([f'L"{c}"' for c in chunks])
        entries.append((rand_id, hash_val, literal))

    table_lines = []
    line_buffer = []
    for i, (rid, hval, lit) in enumerate(entries):
        line_buffer.append(f"{{ 0x{rid:016X}ULL, 0x{hval:016X}ULL, {lit} }}")
        if (i + 1) % ENTRIES_PER_LINE == 0 or i == len(entries) - 1:
            table_lines.append("    " + ", ".join(line_buffer))
            line_buffer = []

    table_body = ",\n".join(table_lines)

    header = f"""#pragma once
#include <cstddef>
#include <cwchar>
#include <cstdint>

struct SerialEntry {{
    uint64_t id;
    uint64_t hash;
    const wchar_t* serial;
}};

static const SerialEntry CAPS[] = {{
{table_body}
}};

static const std::size_t NUM_CAPS = sizeof(CAPS) / sizeof(CAPS[0]);

static const SerialEntry* GetSerialByID(uint64_t id) {{
    for (size_t i = 0; i < NUM_CAPS; i++) {{
        if (CAPS[i].id == id) return &CAPS[i];
    }}
    return nullptr;
}}

static void GetAllIDs(uint64_t* out_ids, size_t max_ids, size_t* written) {{
    *written = 0;
    for (size_t i = 0; i < NUM_CAPS && *written < max_ids; i++) {{
        out_ids[*written] = CAPS[i].id;
        (*written)++;
    }}
}}
"""

    with open(output_file, "w", encoding="utf-8") as out:
        out.write(header)
    print(f"Wrote {output_file} with {len(serials)} serials using OpenCL GPU hashing.")

if __name__ == "__main__":
    main()
