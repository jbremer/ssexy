import os

def assemble(lines):
	lines.insert(0, 'bits 32')
	file('tmp_sseify.asm', 'w').write('\n'.join(lines))
	os.system('yasm -mx86 tmp_sseify.asm')
	ret = open('tmp_sseify', 'rb').read()
	os.unlink('tmp_sseify.asm')
	os.unlink('tmp_sseify')
	return ret
