app = save_regs
board = goodfet42

all: $(app).hex
$(app).hex: $(app).asm
	msp430-as $(app).asm -o $(app)
	msp430-objcopy $(app) -O ihex $(app).hex
install: $(app).hex
	sudo goodfet.bsl -p $(app).hex
reinstall: $(app).hex
	sudo board=$(board) goodfet.bsl -e -p $(app).hex
clean:
	rm -rf $(app)
	rm -rf $(app).hex