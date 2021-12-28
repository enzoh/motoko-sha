MOC := $(shell vessel bin)/moc $(shell vessel sources)

default:
	$(MOC) -wasi-system-api -o Test_SHA256.wasm Test_SHA256.mo && wasmtime Test_SHA256.wasm
	rm -f Test_SHA256.wasm
	$(MOC) -wasi-system-api -o Test_SHA512.wasm Test_SHA512.mo && wasmtime Test_SHA512.wasm
	rm -f Test_SHA512.wasm
