# Copyright (C) 2024 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

SRCDIR = src

.PHONY: all
all: candle_matmul candle_matmul.manifest candle_quantized candle_quantized.manifest
ifeq ($(SGX),1)
all: candle_matmul.manifest.sgx candle_matmul.sig candle_quantized.manifest.sgx candle_quantized.sig
endif

######################### Simple Matrix Multiplication #########################

$(SRCDIR)/candle_matmul/target/debug/candle_matmul:
	mkdir -p $(SRCDIR) && cd $(SRCDIR) && \
		cargo new candle_matmul && cd candle_matmul && \
		cargo add --git https://github.com/huggingface/candle.git candle-core && \
		cp ../../prepared_matmul_src/main.rs ./src/main.rs && \
		cargo build

candle_matmul: $(SRCDIR)/candle_matmul/target/debug/candle_matmul
	cp $< $@

candle_matmul.manifest: candle_matmul.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

candle_matmul.manifest.sgx candle_matmul.sig: candle_matmul_sgx_sign
	@:

.INTERMEDIATE: candle_matmul_sgx_sign
candle_matmul_sgx_sign: candle_matmul.manifest candle_matmul
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

############################## Quantized LLaMA #################################

llama-2-7b.ggmlv3.q4_0.bin:
	../common_tools/download --output $@ \
		--sha256 bfa26d855e44629c4cf919985e90bd7fa03b77eea1676791519e39a4d45fd4d5 \
		--url https://huggingface.co/TheBloke/Llama-2-7B-GGML/resolve/main/$@

tokenizer.json:
	../common_tools/download --output $@ \
		--sha256 8eea70c4866c4f1320ba096fc986ac82038a8374dbe135212ba7628835b4a6f1 \
		--url https://huggingface.co/hf-internal-testing/llama-tokenizer/raw/main/$@

$(SRCDIR)/candle_quantized/target/release/examples/quantized: llama-2-7b.ggmlv3.q4_0.bin tokenizer.json
	mkdir -p $(SRCDIR) && cd $(SRCDIR) && \
		git clone https://github.com/huggingface/candle.git candle_quantized && \
		cd candle_quantized && \
		cargo build --example quantized --release

candle_quantized: $(SRCDIR)/candle_quantized/target/release/examples/quantized
	cp $< $@

candle_quantized.manifest: candle_quantized.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

candle_quantized.manifest.sgx candle_quantized.sig: candle_quantized_sgx_sign
	@:

.INTERMEDIATE: candle_quantized_sgx_sign
candle_quantized_sgx_sign: candle_quantized.manifest candle_quantized
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx
.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest candle_matmul candle_quantized

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) *.tar.gz *.bin *.json
