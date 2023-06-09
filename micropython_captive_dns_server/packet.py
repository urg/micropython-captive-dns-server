import json


class Header:
    """
    This class models a DNS Packet Header

    Header

                                   1  1  1  1  1  1
     0   1  2 3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | ID                                            |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR| Opcode    |AA|TC|RD|RA| Z      | RCODE     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | QDCOUNT                                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | ANCOUNT                                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | NSCOUNT                                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | ARCOUNT                                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    # Network byte order
    BYTE_ORDER = "big"

    def __init__(self):
        self.id: int  # 2 octet. Unique id to identify the request
        self.qr: bool  # 1 bit. Query (0) or Response (1)
        self.opcode: int  # 4 bits. Type of query. 0 is standard
        self.aa: bool  # 1 bit. Authoritative Answer
        self.tc: bool  # 1 bit. Truncation
        self.rd: bool  # 1 bit. Recursion desired
        self.ra: bool  # 1 bit. Recuration available
        self.z: int  # 4 bits. Reserved for future use. Must be 0
        self.rcode: int  # 4 bits. Response code. 0 is no error
        self.qdcount: int  # 2 octets. unsigned int questions
        self.ancount: int  # 2 octets. unsigned int resource records
        self.nscount: int  # 2 octets. unsigned int name server
        self.arcount: int  # 2 octets. unsigned int additional records

    def unpack(self, data):
        self.id = int.from_bytes(data[:2], self.BYTE_ORDER)
        combined_bytes = int.from_bytes(data[2:4], self.BYTE_ORDER)
        self.qr = combined_bytes & (1 << 15 - 0) > 0
        self.opcode = combined_bytes & (1 << 3 << 15 - 1)
        self.aa = combined_bytes & (1 << 15 - 5) > 0
        self.tc = combined_bytes & (1 << 15 - 6) > 0
        self.rd = combined_bytes & (1 << 15 - 7) > 0
        self.ra = combined_bytes & (1 << 15 - 8) > 0
        self.z = combined_bytes & (1 << 3 << 15 - 9)
        self.rcode = combined_bytes & (1 << 3 << 15 - 12)
        self.qdcount = int.from_bytes(data[4:6], self.BYTE_ORDER)
        self.ancount = int.from_bytes(data[6:8], self.BYTE_ORDER)
        self.nscount = int.from_bytes(data[8:10], self.BYTE_ORDER)
        self.arcount = int.from_bytes(data[10:12], self.BYTE_ORDER)

    def pack(self):
        packet = int.to_bytes(self.id, 2, self.BYTE_ORDER)
        combined_bytes = 0
        if self.qr:
            combined_bytes = combined_bytes | (1 << 15 - 0)
        if self.aa > 0:
            combined_bytes = combined_bytes | (1 << 15 - 5)
        if self.tc > 0:
            combined_bytes = combined_bytes | (1 << 15 - 6)
        if self.rd > 0:
            combined_bytes = combined_bytes | (1 << 15 - 7)
        if self.ra > 0:
            combined_bytes = combined_bytes | (1 << 15 - 8)
        # todo: self.z, self.rcode, self.opcode
        packet += int.to_bytes(combined_bytes, 2, self.BYTE_ORDER)
        packet += int.to_bytes(self.qdcount, 2, self.BYTE_ORDER)
        packet += int.to_bytes(self.ancount, 2, self.BYTE_ORDER)
        packet += int.to_bytes(self.nscount, 2, self.BYTE_ORDER)
        packet += int.to_bytes(self.arcount, 2, self.BYTE_ORDER)

        return packet

    def __str__(self):
        return json.dumps(
            {
                "id": self.id,
                "qr": self.qr,
                "opcode": self.opcode,
                "aa": self.aa,
                "tc": self.tc,
                "rd": self.rd,
                "ra": self.ra,
                "z": self.z,
                "rcode": self.rcode,
                "qdcount": self.qdcount,
                "ancount": self.ancount,
                "nscount": self.nscount,
                "arcount": self.arcount,
            },
            indent=4,
        )


class Question:
    """
    This class models a DNS Packet Question

    Question

                                   1  1  1  1  1  1
     0   1  2 3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    / QNAME                                         /
    /                                               /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | QTYPE                                         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | QCLASS                                        |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    # Network byte order
    BYTE_ORDER = "big"

    def __init__(self):
        self.qname: str = ""
        self.qtype: str
        self.qclass: str

    def unpack(self, packet, position):
        # length of this label defined in first byte
        length = packet[position]
        # qname is 0 terminated
        while length != 0:
            label = position + 1
            # add the label to the requested domain and insert a dot after
            self.qname += packet[label:label + length].decode("utf-8") + "."
            # check if there is another label after this one
            position += length + 1
            length = packet[position]
        # advance past the 0 terminiation
        position += 1

        self.qtype = int.from_bytes(
            packet[position:position + 2], self.BYTE_ORDER
        )
        position += 2

        self.qclass = int.from_bytes(
            packet[position:position + 2], self.BYTE_ORDER
        )
        position += 2

        return position

    def pack(self):
        packet = b""
        for label in self.qname.split("."):
            packet += int.to_bytes(len(label), 1, self.BYTE_ORDER)
            packet += bytes(label, "utf-8")
        packet += int.to_bytes(self.qtype, 2, self.BYTE_ORDER)
        packet += int.to_bytes(self.qclass, 2, self.BYTE_ORDER)

        return packet

    def __str__(self):
        return json.dumps(
            {"qname": self.qname, "qtype": self.qtype, "qclass": self.qclass},
            indent=4,
        )


class Answer:
    """
    This class models a DNS Packet Answer

    Answer

                                   1  1  1  1  1  1
     0   1  2 3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    / NAME                                         /
    /                                               /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | TYPE                                          |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | CLASS                                         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | TTL                                           |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | RDLENGTH                                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    / RDATA                                         /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    # Network byte order
    BYTE_ORDER = "big"

    def __init__(self):
        self.aname: str
        self.atype: int
        self.aclass: int
        self.ttl: int
        self.rdlength: int
        self.rddata: str

    def answer_ip(self, question: Question, ip: str):
        self.aname = question.qname
        self.atype = 1
        self.aclass = 1
        self.ttl = 1
        self.rdlength = 4
        self.rddata = ip

    def pack(self):
        packet = b""
        for label in self.aname.split("."):
            packet += int.to_bytes(len(label), 1, self.BYTE_ORDER)
            packet += bytes(label, "utf-8")
        # packet += b'0x0'
        packet += int.to_bytes(self.atype, 2, self.BYTE_ORDER)
        packet += int.to_bytes(self.aclass, 2, self.BYTE_ORDER)
        packet += int.to_bytes(self.ttl, 4, self.BYTE_ORDER)
        packet += int.to_bytes(self.rdlength, 2, self.BYTE_ORDER)
        packet += bytes(map(int, self.rddata.split(".")))
        return packet

    def __str__(self):
        return json.dumps(
            {
                "name": self.aname,
                "type": self.atype,
                "class": self.aclass,
                "ttl": self.ttl,
                "rdlength": self.rdlength,
                "rddata": self.rddata,
            },
            indent=4,
        )


class DNSPacket:
    """
    This class models a DNS Packet

    Packet

    +---------------------+
    | Header              |
    +---------------------+
    | Question            | Question for the name server
    +---------------------+
    | Answer              | Answers to the question
    +---------------------+
    | Authority           | Not implemented
    +---------------------+
    | Additional          | Not implemented
    +---------------------+

    """

    def __init__(self, ip_response: str):
        self.header: Header = Header()
        self.questions: list[Question] = []
        self.answers: list[Answer] = []
        self.ip_response: str = ip_response

    def answer(self):
        for question in self.questions:
            answer = Answer()
            answer.answer_ip(question, self.ip_response)
            self.answers.append(answer)
        self.header.qr = True
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = 0
        self.header.arcount = 0

        return self.pack()

    def unpack(self, packet):
        self.header.unpack(packet)
        position = 12

        for i in range(0, self.header.qdcount):
            question = Question()
            position = question.unpack(packet, position)
            self.questions.append(question)

        # we're just doing a simple question / answer server at the moment
        # so ignoring anything beyond the question

    def pack(self):
        packet = self.header.pack()
        for question in self.questions:
            packet += question.pack()
        for answer in self.answers:
            packet += answer.pack()

        return packet
