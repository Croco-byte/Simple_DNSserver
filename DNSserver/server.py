# Imports
import socket, binascii, glob, json
from DNSserver.classes.DNSclasses import DNSrequest, DNSresponse
from DNSserver.utils.utilities import format_hex

# Load zone data in global variable
def load_zones():
    jsonzones = {}
    zonefiles = glob.glob("zones/*.zone")

    for zonefile in zonefiles:
        with open(zonefile) as file:
            data = json.load(file)
            zone_name = data["$origin"]
            jsonzones[zone_name] = data
    return jsonzones

zone_data = load_zones()


def get_zone(target_domain):
    global zone_data
    return zone_data[target_domain]


def get_flags(req_header):
    QR      =   '1'
    OPCODE  =   req_header.Opcode
    AA      =   '1'
    TC      =   '0'
    RD      =   '0'
    RA      =   '0'
    Z       =   '0'
    AD      =   '0'
    CD      =   '0'
    RCODE   =   '0000'

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder="big") + int(RA+Z+AD+CD+RCODE, 2).to_bytes(1, byteorder="big")


def get_records(request):
    target_domain = request.question.domainstring
    question_type = 'a' if request.question.qtype == b'\x00\x01' else '?'
    zone_data = get_zone(target_domain)
    
    return zone_data[question_type]


def build_response(data):
    
    # Parsing request
    request = DNSrequest(data)
    print("\n")
    print(request)

    # Getting zone informations for the request
    records = get_records(request)

    # Preparing response - setting header and question
    response = DNSresponse(request.question)
    response.header.id = request.header.id
    response.header.flags = get_flags(request.header)
    response.header.qdcount = b'\x00\x01'
    response.header.ancount = len(records).to_bytes(2, byteorder="big")
    response.header.nscount = b'\x00\x00'
    response.header.arcount = b'\x00\x00'

    # Preparing response - setting answer(s)
    for record in records:
        response.add_answer_entry(b"\xc0\x0c", b'\x00\x01', record["ttl"].to_bytes(4, byteorder="big"), socket.inet_aton(record["value"]))

    print("\n")
    print(response)
    print("\n Here's the response as bytes :")
    print(format_hex(binascii.hexlify(response.response_to_bytes()).decode()))

    return response.response_to_bytes()



def run():
    ip = "127.0.0.1"
    port = 53

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.bind((ip, port))

    while 1:
        data, addr = sock.recvfrom(512)
        print("[*] Received the following data from {}, port {} :".format(addr[0], addr[1]))
        print(format_hex(binascii.hexlify(data).decode()))

        r = build_response(data)
        sock.sendto(r, addr)