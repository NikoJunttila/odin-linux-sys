.PHONY: all clean game inject injector

all: game inject injector

# Build the 32-bit Odin game
game:
	odin build . -target:linux_i386 -extra-linker-flags:"-m32" -out:main32

# Build the injectable shared library
inject:
	gcc -m32 -shared -fPIC -o inject.so inject.c

# Build the ptrace injector
injector:
	gcc -m32 -o injector injector.c -ldl

clean:
	rm -f main32 inject.so injector

# Usage instructions
help:
	@echo "Usage:"
	@echo "  make all       - Build everything"
	@echo "  make game      - Build the 32-bit Odin game"
	@echo "  make inject    - Build the injectable .so"
	@echo "  make injector  - Build the ptrace injector"
	@echo ""
	@echo "To inject:"
	@echo "  1. Run the game:  ./main32"
	@echo "  2. Get PID:       pgrep main32"
	@echo "  3. Inject:        sudo ./injector <pid> $(PWD)/inject.so"
