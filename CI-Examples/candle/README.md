# Candle

Candle is a minimalist ML framework for Rust with a focus on performance
(including GPU support) and ease of use: https://github.com/huggingface/candle

This directory contains the Makefile and the template manifest for the most
recent version of Candle as of this writing (v0.6.0).

# Warning

The `candle_quantized` app will download ~4GB of data (model + tokenizer). This
happens automatically in the Makefile.

# Quick Start

```sh
# build Candle (uses Rust Cargo) and the final manifest
make SGX=1

# run simple matrix multiplication
# example taken from https://github.com/huggingface/candle/tree/0.6.0?tab=readme-ov-file#get-started
./candle_matmul
gramine-direct ./candle_matmul
gramine-sgx ./candle_matmul

# run Quantized LLaMA (quantized version of the LLaMA model)
# note that for Gramine, the cmdline args are already defined in the manifest file
# example taken from https://github.com/huggingface/candle/tree/0.6.0?tab=readme-ov-file#check-out-our-examples
RAYON_NUM_THREADS=36 ./candle_quantized \
    --model llama-2-7b.ggmlv3.q4_0.bin --tokenizer tokenizer.json --sample-len 200
RAYON_NUM_THREADS=36 gramine-direct ./candle_quantized
RAYON_NUM_THREADS=36 gramine-sgx ./candle_quantized
```
