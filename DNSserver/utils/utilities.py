def format_hex(hex):
	octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
	return (" ".join(octets))