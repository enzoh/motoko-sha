default:
	$(shell vessel bin)/moc $(shell vessel sources) -wasi-system-api -o Test_SHA256.wasm Test_SHA256.mo && wasmtime Test_SHA256.wasm
	rm -f Test_SHA256.wasm
