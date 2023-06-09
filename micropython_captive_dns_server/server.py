import usocket as socket
import uasyncio as asyncio
from packet import DNSPacket
import gc


class CaptiveDNSServer:
    async def run(self, response_ip):
        try:
            udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # set non-blocking otherwise execution will stop at 'recvfrom'
            # until a connection is received and this will prevent the other
            # async threads from running
            udps.setblocking(False)

            addr = socket.getaddrinfo(
                "0.0.0.0", 53, socket.AF_INET, socket.SOCK_DGRAM
            )[0][4]
            udps.bind(addr)
            print("Starting server on port 53")
        except Exception:
            print("Failed to bind to port")
            return

        while True:
            try:
                gc.collect()

                data, addr = udps.recvfrom(4096)
                print("Incoming data...")
                print(data)

                dns_packet = DNSPacket(response_ip)
                dns_packet.unpack(data)

                udps.sendto(dns_packet.answer(), addr)

                print(
                    "Replying: {:s} -> {:s}".format(
                        dns_packet.questions[0].qname, response_ip
                    )
                )

                await asyncio.sleep_ms(100)

            except Exception:
                await asyncio.sleep_ms(500)

        udps.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    server = CaptiveDNSServer()
    loop.create_task(server.run("192.168.4.1"))
    loop.run_forever()
    loop.close()
