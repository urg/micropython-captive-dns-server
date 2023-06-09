import unittest
from ..packet import Header, Question, DNSPacket, Answer


class TestHeader(unittest.TestCase):
    def test_header(self):
        packet = b"\x83\x8d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

        header = Header()
        header.unpack(packet)

        # print(header)

        self.assertEqual(header.pack(), packet)
        self.assertEqual(header.qr, False)
        self.assertEqual(header.opcode, 0)
        self.assertEqual(header.aa, False)
        self.assertEqual(header.tc, False)
        self.assertEqual(header.rd, True)
        self.assertEqual(header.ra, False)
        self.assertEqual(header.z, 0)
        self.assertEqual(header.rcode, 0)
        self.assertEqual(header.qdcount, 1)
        self.assertEqual(header.ancount, 0)
        self.assertEqual(header.nscount, 0)
        self.assertEqual(header.arcount, 0)


class TestQuestion(unittest.TestCase):
    def test_question(self):
        packet = b"\x83\x8d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            b"\x06foobar\x03com\x00\x00\x01\x00\x01\x00\x00)\x10" \
            b"\x00\x00\x00\x00\x00\x00\x00\x00"

        question = Question()
        position = question.unpack(packet, 12)

        # print(question)

        self.assertEqual(question.qname, "foobar.com.")
        self.assertEqual(question.qclass, 1)
        self.assertEqual(question.qtype, 1)
        self.assertEqual(position, 28)

        self.assertEqual(
            question.pack(), b"\x06foobar\x03com\x00\x00\x01\x00\x01"
        )


class TestAnswer(unittest.TestCase):
    def test_answer(self):
        packet = b"\x83\x8d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            b"\x06foobar\x03com\x00\x00\x01\x00\x01\x00\x00)\x10" \
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        expected = b"\x06foobar\x03com\x00\x00\x01\x00\x01\x00\x00\x00" \
            b"\x01\x00\x04\x7f\x00\x00\x02"
        question = Question()
        question.unpack(packet, 12)
        answer = Answer()
        answer.answer_ip(question, "127.0.0.2")

        # print(answer)

        self.assertEqual(answer.aname, "foobar.com.")
        self.assertEqual(answer.atype, 1)
        self.assertEqual(answer.aclass, 1)
        self.assertEqual(answer.ttl, 1)
        self.assertEqual(answer.rdlength, 4)
        self.assertEqual(answer.rddata, "127.0.0.2")
        self.assertEqual(
            answer.pack(),
            expected
        )


class TestDNSPacket(unittest.TestCase):
    def test_dnspacket(self):
        packet = b"\x83\x8d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            b"\x06foobar\x03com\x00\x00\x01\x00\x01\x00\x00)\x10" \
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        expected = b"\x83\x8d\x81\x00\x00\x01\x00\x01\x00\x00\x00\x00" \
            b"\x06foobar\x03com\x00\x00\x01\x00\x01" \
            b"\x06foobar\x03com\x00\x00\x01\x00\x01" \
            b"\x00\x00\x00\x01\x00\x04\x7f\x00\x00\x02"

        dns_packet = DNSPacket("127.0.0.2")
        dns_packet.unpack(packet)
        response = dns_packet.answer()

        print(dns_packet.header)
        print(dns_packet.questions[0])
        print(dns_packet.answers[0])

        self.assertEqual(response, expected)


if __name__ == "__main__":
    unittest.main()
