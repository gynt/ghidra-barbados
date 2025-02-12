#Find AOB at current address
#@author 
#@category Barbados.Python
#@keybinding 
#@menupath 
#@toolbar bomb.png

CONFIG_SET_ADDRESS_DETECTION = True
CONFIG_SET_SAFE_INSTRUCTIONS = True

import struct

from __main__ import currentProgram
from __main__ import currentAddress
from __main__ import findBytes
from __main__ import toAddr

import ghidra.program.database.code.DataDB as DataDB
import ghidra.program.database.code.InstructionDB as InstructionDB

SAFE_INSTRUCTIONS = [
	# IMUL EAX, EAX, value
	[0x69, 0xc0],
	# IMUL EBX, EBX, value
	[0x69, 0xdb],
	[0x0f, 0xbf, 0x83],
]

def startsWithBytes(a, start):
	for i in range(0, len(start)):
		if a[i] != start[i]:
			return False
	return True

def getSafeStartingBytes(codeUnit):
	if codeUnit.getMnemonicString() == "IMUL":
		return codeUnit.getLength()
	b = codeUnit.getBytes()
	for safeInstructionBytes in SAFE_INSTRUCTIONS:
		if startsWithBytes(b, safeInstructionBytes):
			return len(safeInstructionBytes)
	return 0

def instructionHasAddress(codeUnit):
	for i in range(codeUnit.getNumOperands()):
		for opObject in codeUnit.getOpObjects(i):
			if type(opObject).__name__ == "GenericAddress":
				return True
			if type(opObject).__name__ == "Scalar":
				if opObject.getSignedValue() >= 0x400000:
					return True
	return False

def hasMultipleMatches(stream):
	i = 0
	f = findBytes(currentProgram.getMinAddress(), stream)
	while f:
		i += 1
		f = findBytes(toAddr(f.getOffset() + 1), stream)
		if i > 1:
			return True
	return False

def findCodeAOB(addr, maxlen = 1000):
	
	l = currentProgram.getListing()
	fm = currentProgram.getFunctionManager()
	
	ca = addr
	
	
	
	text = ""
	stream = b''
	bs = 0
	
	f = fm.getFunctionContaining(ca)
	c = l.getCodeUnitAt(ca)
	while bs < maxlen:
		b = c.getBytes()
		bs += len(b)

		if (len(b) <= 4) or (instructionHasAddress(c) == False and CONFIG_SET_ADDRESS_DETECTION):
			stream += (''.join(["\\x{:02X}".format( struct.unpack("B", struct.pack("b", bv))[0]) for bv in b]))
			text += (' '.join(["{:02X}".format(struct.unpack("B", struct.pack("b", bv))[0]) for bv in b]))
			text += ' '		
		else:
			sb = 0
			if CONFIG_SET_SAFE_INSTRUCTIONS:
				sb = getSafeStartingBytes(c)
			if sb == 0:
				sb = 1
			stream += (''.join(["\\x{:02X}".format( struct.unpack("B", struct.pack("b", bv))[0]) for bv in b[:sb]]))
			text += (' '.join(["{:02X}".format( struct.unpack("B", struct.pack("b", bv))[0]) for bv in b[:sb]]))
			text += ' '
			count = len(b) - sb
			stream += b'.{' + str(count) + b'}'
			text += '? ' * count
	
		cn = c.getNext()
		
		if cn.getAddress().getOffset() - c.getAddress().getOffset() != c.getLength():
			# We made a jump! (happens when jumping to a next function)
			raise Exception("No AOB found with a single match before end of function was reached: " + str(c.getAddress()) + "\nDEBUG: " + text) 

		f2 = fm.getFunctionContaining(c.getAddress())

		if f != f2:
			print("INFO: We might be moving to a different function: " + str(c.getAddress())) 

		c = cn	
		if not hasMultipleMatches(stream):
			break
	
	if bs >= maxlen:
		# print("WARNING: Reached maximum search length!")
		# print("INFO: matches found " + (" > 1" if hasMultipleMatches(stream) else " 1 "))
		raise Exception("Reached maximum search length! length: " + str(maxlen) + "\nDEBUG: " + text)
	
	# print("FOUND AOB for: 0x" + ca.toString())
	# print(text)
	
	return ca, text

def findDataAOB(addr, maxlen = 1000, increment = 4):
	
	l = currentProgram.getListing()
	fm = currentProgram.getFunctionManager()
	
	ca = addr
	
	
	
	text = ""
	stream = b''
	bs = 0
	
	c = l.getCodeUnitAt(ca)
	while bs < maxlen:
		b = c.getBytes()
		bs += len(b)

		if bs >= maxlen:
			trim = maxlen - (bs - len(b))
			stream += (''.join(["\\x{:02X}".format( struct.unpack("B", struct.pack("b", bv))[0]) for bv in b[:trim]]))
			text += (' '.join(["{:02X}".format(struct.unpack("B", struct.pack("b", bv))[0]) for bv in b[:trim]]))
			text += ' '
			
			if hasMultipleMatches(stream):
				raise Exception("Reached maximum search length! length: " + str(maxlen) + "\nDEBUG: " + text)
			else:
				break
		else:
			unique = False
			for i in range(0, len(b), 4):				
				streamtry = stream + (''.join(["\\x{:02X}".format( struct.unpack("B", struct.pack("b", bv))[0]) for bv in b[:(i+1)]]))
				texttry = text + (' '.join(["{:02X}".format(struct.unpack("B", struct.pack("b", bv))[0]) for bv in b[:(i+1)]])) + ' '
				
				if not hasMultipleMatches(streamtry):
					return ca, texttry
				
				text = texttry
				steam = streamtry
	
			cn = l.getCodeUnitAt(toAddr(c.getAddress().getOffset() + len(b)))
		
			if cn.getAddress().getOffset() - c.getAddress().getOffset() != c.getLength():
				# We made a jump! (happens when jumping to a next function)
				raise Exception("No AOB found with a single match before end of function was reached: " + str(c.getAddress()) + "\nDEBUG: " + text) 

			c = cn	
			if not hasMultipleMatches(stream):
				return ca, text
	
	if bs >= maxlen:
		# print("WARNING: Reached maximum search length!")
		# print("INFO: matches found " + (" > 1" if hasMultipleMatches(stream) else " 1 "))
		raise Exception("Reached maximum search length! length: " + str(maxlen) + "\nDEBUG: " + text)
	
	# print("FOUND AOB for: 0x" + ca.toString())
	# print(text)
	
	return ca, text	

def findAOB(addr, maxlen = 1000, increment = 4):
	if isinstance(currentProgram.getListing().getCodeUnitAt(addr), DataDB):
		ca, text = findDataAOB(currentAddress)
	elif isinstance(currentProgram.getListing().getCodeUnitAt(addr), InstructionDB):
		ca, text = findCodeAOB(currentAddress)
	else:
		raise Exception("Undefined info in listing")
	return ca, text

if __name__ == "__main__":

	ca, text = findAOB(currentAddress)

	print("FOUND AOB for: 0x" + ca.toString())
	print(text)
