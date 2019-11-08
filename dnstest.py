import socketserver
import argparse
import io

from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A, DNSQuestion, TXT, QTYPE

d = DNSRecord(DNSHeader(qr=1,aa=1,ra=1),
              q=DNSQuestion("abc.com"),
              a=RR("abc.com",rdata=A("1.2.3.4")))

class DNSHandler(socketserver.BaseRequestHandler):
  def handle(self):
    data = self.request[0]
    socket = self.request[1]
    
    d = DNSRecord.parse(data)
    q = d.questions[0]
    name = '.'.join(map(lambda x: x.decode('utf-8'), q.qname.label))
    a = d.reply()
    a.add_answer(RR(name, QTYPE.A, rdata=A("1.2.3.4")))
    a.add_answer(RR(name, QTYPE.TXT,rdata=TXT("Mytest")))
    socket.sendto(a.pack(), self.client_address)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Simple TXT DNS server')
  parser.add_argument('port', metavar='port', type=int,
                      help='port to listen on')

  args = parser.parse_args()
  port = args.port

  server = socketserver.ThreadingUDPServer(('', port), DNSHandler)
  print('Running on port %d' % port)

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    server.shutdown()


