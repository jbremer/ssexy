import sys, binascii, distorm3, enc

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Usage: python %s <machine-code>' % sys.argv[0]
		exit(0)
	
	# get hex
	code = binascii.unhexlify(sys.argv[1])
	
	# encode the instructions to sse
	lines = []
	for dis in distorm3.DecomposeGenerator(0, code, distorm3.Decode32Bits):
		lines += enc.Enc(dis).encode()
	
	# print the instructions
	print '"' + '\\n"\r\n"'.join(lines) + '\\n"'