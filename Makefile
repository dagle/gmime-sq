HEADERS = \
	include/galore-sq-context.h

RUST_SOURCES = \
	src/lib.rs \
	src/galore_sq_context/imp.rs \
	src/galore_sq_context/mod.rs \
	src/galore_sq_context/sq.rs

all: GaloreSq-0.1.gir GaloreSq-0.1.typelib

export PKG_CONFIG_PATH=$(PWD)
export GI_TYPELIB_PATH=$(PWD)
export LD_LIBRARY_PATH=$(PWD)/target/debug

target/debug/libgalore_sq.so: $(RUST_SOURCES)
	cargo build

GaloreSq-0.1.gir: target/debug/libgalore_sq.so $(HEADERS)
	g-ir-scanner -v --warn-all \
		--namespace GaloreSq --nsversion=0.1 \
		-Iinclude --c-include "galore-sq-context.h" \
		--library=galore_sq --library-path=target/debug \
		--include=GMime-3.0 --include=Gio-2.0 \
		--include=GObject-2.0 -pkg gobject-2.0 \
		--output $@ \
		$(HEADERS)

GaloreSq-0.1.typelib: GaloreSq-0.1.gir
	g-ir-compiler \
		--includedir=include \
		$< -o $@

# Sq-0.1.vapi: Sq-0.1.gir
# 	vapigen \
# 		--library Sq-0.1 \
# 		$<

clean:
	rm -f GaloreSq-0.1.typelib
	rm -f GaloreSq-0.1.gir
	rm -f GaloreSq-0.1.vapi test-vala
	rm -rf test-c
	cargo clean

run-python: GaloreSq-0.1.typelib
	python3 test.py

run-gjs: Sq-0.1.typelib
	gjs test.js

# test-vala: test.vala Sq-0.1.vapi
# 	valac -v \
# 		--vapidir=$(PWD) \
# 		--pkg=Ex-0.1 \
# 		$< -o $@

run-vala: test-vala
	./test-vala

test-c: test.c target/debug/libgalore_sq.so sq-0.1.pc $(HEADERS)
	$(CC) -Wall $< `pkg-config --cflags --libs Ex-0.1` -o $@

run-c: test-c
	./test-c

check:
	cargo test

check-bindings: target/debug/libgalore_sq.so
	cargo test --features=bindings

check-all: check check-bindings run-c run-python run-gjs run-vala