import socket, binascii

from DNSserver.classes.DNSexceptions import DNSRequestFormatError

class DNSheader(object):
	def __init__(self, raw_header):
		self.id         = raw_header[:2]
		self._flags     = raw_header[2:4]
		self.qdcount    = raw_header[4:6]
		self.ancount    = raw_header[6:8]
		self.nscount    = raw_header[8:10]
		self.arcount    = raw_header[10:]

		self.getFlagsDetails()

	def _set_flags(self, new_value):
		self._flags = new_value
		self.getFlagsDetails()

	def getFlagsDetails(self):
		flags_first_byte = "{:08b}".format(self._flags[0])
		flags_second_byte = "{:08b}".format(self._flags[1])

		self.QR			= flags_first_byte[0:1]
		self.Opcode		= flags_first_byte[1:5]
		self.AA			= flags_first_byte[5:6]
		self.TC			= flags_first_byte[6:7]
		self.RD			= flags_first_byte[7:8]
		self.RA			= flags_second_byte[0:1]
		self.Z			= flags_second_byte[1:2]
		self.AD			= flags_second_byte[2:3]
		self.CD			= flags_second_byte[3:4]
		self.Rcode		= flags_second_byte[4:8]

	def header_to_bytes(self):
		return self.id + self._flags + self.qdcount + self.ancount + self.nscount + self.arcount

	def __str__(self):
		end_message = []
		end_message.append(" == DNS header ==")
		end_message.append("> Transaction ID:		0x{}".format(binascii.hexlify(self.id).decode()))
		end_message.append("> Flags:			0x{}".format(binascii.hexlify(self._flags).decode()))
		end_message.append("    - QR:       {}".format(self.QR))
		end_message.append("    - Opcode:   {}".format(int(self.Opcode, 2)))
		end_message.append("    - AA:       {}".format(self.AA))
		end_message.append("    - TC:       {}".format(self.TC))
		end_message.append("    - RD:       {}".format(self.RD))
		end_message.append("    - RA:       {}".format(self.RA))
		end_message.append("    - Z:        {}".format(self.Z))
		end_message.append("    - AD:	{}".format(self.AD))
		end_message.append("    - CD:	{}".format(self.CD))
		end_message.append("    - Rcode:    {}".format(int(self.Rcode, 2)))
		end_message.append("> QDCOUNT:			0x{}".format(binascii.hexlify(self.qdcount).decode()))
		end_message.append("> ANCOUNT:			0x{}".format(binascii.hexlify(self.ancount).decode()))
		end_message.append("> NSCOUNT:			0x{}".format(binascii.hexlify(self.nscount).decode()))
		end_message.append("> ARCOUNT:			0x{}".format(binascii.hexlify(self.arcount).decode()))
		return ("\n".join(end_message))
	
	flags = property(None, _set_flags)

class DNSquestion:
    def __init__(self, raw_data):
        self.labels = []

        i = 0
        while (raw_data[i] != 0):
            label_len = raw_data[i]
            self.labels.append(raw_data[i+1:i+1+label_len].decode())
            i += raw_data[i] + 1
		
        i += 1
        self.qtype = raw_data[i:i+2]
        i += 2
        self.qclass = raw_data[i:i+2]
        self.raw_question = raw_data[:i+2]
        self.domainstring = '.'.join(self.labels) + '.'

    def question_to_bytes(self):
        return self.raw_question

    def __str__(self):
        end_message = []
        end_message.append("\n == Question ==")
        end_message.append("> Queried domain:		{}".format('.'.join(self.labels)))
        end_message.append("> QTYPE:			{}".format(binascii.hexlify(self.qtype).decode()))
        end_message.append("> QCLASS:			{}".format(binascii.hexlify(self.qclass).decode()))
        return ("\n".join(end_message))


class DNSanswer:
    def __init__(self, name, rtype, ttl, answer_data):
        self.name = name
        self.rtype = rtype
        self.rclass = b'\x00\x01'
        self.ttl = ttl
        self.rdlength = b'\x00\x04'
        self.answer_data = answer_data
    
    def answer_to_bytes(self):
        return self.name + self.rtype + self.rclass + self.ttl + self.rdlength + self.answer_data

    def __str__(self):
        end_message = []
        end_message.append("\n == Answer ==")
        end_message.append("> Name offset:    	        0x{}".format(binascii.hexlify(self.name).decode()))
        end_message.append("> Type:         		0x{}".format(binascii.hexlify(self.rtype).decode()))
        end_message.append("> Class:        		0x{}".format(binascii.hexlify(self.rclass).decode()))
        end_message.append("> TTL:          		{}".format(int.from_bytes(self.ttl, 'big')))
        end_message.append("> RDATA:        		{}".format(socket.inet_ntoa(self.answer_data)))
        return '\n'.join(end_message)


class DNSrequest:
	def __init__(self, raw_data):
		self.header		= DNSheader(raw_data[0:12])
		self.question	= DNSquestion(raw_data[12:])


	def __str__(self):
		end_message = []
		end_message.append("#### RECEIVED REQUEST ####")
		end_message.append(self.header.__str__())
		end_message.append(self.question.__str__())
		return '\n'.join(end_message)


class DNSresponse:
    def __init__(self, question):
        self.header         = DNSheader(b'\x00' * 12)
        self.question       = question
        self.answer_entries = []

    def add_answer_entry(self, name, rtype, ttl, answer_data):
        self.answer_entries.append(DNSanswer(name, rtype, ttl, answer_data))

    def response_to_bytes(self):
        entries_as_bytes = b''
        for entry in self.answer_entries:
            entries_as_bytes += entry.answer_to_bytes()
        return (self.header.header_to_bytes() + self.question.question_to_bytes() + entries_as_bytes)

    def __str__(self):
        end_message = []
        end_message.append("#### SENDING RESPONSE ####")
        end_message.append(self.header.__str__())
        end_message.append(self.question.__str__())
        for answer in self.answer_entries:
            end_message.append(answer.__str__())
        return '\n'.join(end_message)