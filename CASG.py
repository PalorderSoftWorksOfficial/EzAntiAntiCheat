import pyopencl as cl
import numpy as np
import os
import time

DEFAULT_INPUT = "SerialKeys.txt"
DEFAULT_OUTPUT = "SerialKeys.txt"
DEFAULT_COUNT = 1
VRAM_LIMIT_GB = 8
SERIAL_MASK = "#####-#####-#####-#####-#####-#####-#####-#####-#####-##########-#####-#####-#####-#####-#####-#####-#####-#####-#####"
ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

SUB_BATCH = 100_000  # Generate 100k serials at a time

def select_gpu():
    platforms = cl.get_platforms()
    devices = sum([p.get_devices() for p in platforms], [])
    if not devices:
        raise RuntimeError("No OpenCL devices found.")
    print("Available GPUs:")
    for i, dev in enumerate(devices):
        vram = getattr(dev, "global_mem_size", 0) / (1024**3)
        print(f"{i}: {dev.name} {vram:.2f}GB VRAM")
    idx = input("Select GPU [0]: ").strip()
    idx = int(idx) if idx.isdigit() and int(idx) < len(devices) else 0
    dev = devices[idx]
    vram = getattr(dev, "global_mem_size", 0) / (1024**3)
    print(f"Using GPU: {dev.name} ({vram:.2f} GB VRAM)\n")
    ctx = cl.Context([dev])
    queue = cl.CommandQueue(ctx)
    return ctx, queue, dev

def generate_serials_gpu(count, mask, ctx, queue, kernel):
    mask_len = len(mask)
    serials_written = 0
    with open(DEFAULT_OUTPUT, "a", encoding="utf-8") as f:
        while serials_written < count:
            current_batch = min(SUB_BATCH, count - serials_written)
            rand_buf_np = np.random.randint(0, len(ALPHANUM), size=current_batch * mask_len, dtype=np.uint8)
            output_np = np.empty_like(rand_buf_np)
            mf = cl.mem_flags
            rand_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=rand_buf_np)
            output_buf = cl.Buffer(ctx, mf.WRITE_ONLY, output_np.nbytes)

            kernel(queue, (current_batch,), None, rand_buf, output_buf, np.uint32(len(ALPHANUM)))
            cl.enqueue_copy(queue, output_np, output_buf)
            queue.finish()

            for i in range(current_batch):
                serial_chars = [ALPHANUM[output_np[i * mask_len + j] % len(ALPHANUM)] if c == "#" else c
                                for j, c in enumerate(mask)]
                f.write(''.join(serial_chars) + "\n")
                serials_written += 1
                print(f"[{serials_written}/{count}]", end='\r', flush=True)
    print("\n")
    return serials_written

def main():
    global DEFAULT_INPUT, DEFAULT_OUTPUT
    inp = input(f"Input file [{DEFAULT_INPUT}]: ").strip()
    DEFAULT_INPUT = inp if inp else DEFAULT_INPUT
    outp = input(f"Output file [{DEFAULT_OUTPUT}]: ").strip()
    DEFAULT_OUTPUT = outp if outp else DEFAULT_OUTPUT
    count_inp = input(f"Number of serials [{DEFAULT_COUNT}]: ").strip()
    count = int(count_inp) if count_inp.isdigit() else DEFAULT_COUNT

    ctx, queue, dev = select_gpu()

    kernel_src = f"""
    __kernel void generate_serials(__global const uchar *rand_buf, __global uchar *output, const uint alphanum_len) {{
        int gid = get_global_id(0);
        int offset = gid * {len(SERIAL_MASK)};
        for(int i = 0; i < {len(SERIAL_MASK)}; i++) {{
            output[offset + i] = rand_buf[offset + i];
        }}
    }}
    """
    prg = cl.Program(ctx, kernel_src).build()
    kernel = cl.Kernel(prg, "generate_serials")

    start_time = time.time()
    total_generated = generate_serials_gpu(count, SERIAL_MASK, ctx, queue, kernel)
    elapsed = time.time() - start_time
    print(f"Generated {total_generated} serials in {elapsed:.2f}s.")

if __name__ == "__main__":
    while True:
        main()
        again = input("Generate more serial keys? [y/n]: ").strip().lower()
        if again != 'y':
            print("Exiting Serial Generator.")
            break
