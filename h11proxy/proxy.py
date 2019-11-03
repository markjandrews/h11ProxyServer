import argparse
import asyncio
import gzip
import logging
import ssl
import sys
from asyncio import transports, AbstractEventLoop
from http import HTTPStatus
from typing import Optional, Tuple

import h11
import requests

from h11proxy.request import ProxyRequest

responses = {
    v: (v.phrase, v.description)
    for v in HTTPStatus.__members__.values()
}

logging.basicConfig()

DEFAULT_LOG_LEVEL = logging.DEBUG

# Default error message template
DEFAULT_ERROR_MESSAGE = """\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: {code}</p>
        <p>Message: {message}.</p>
        <p>Error code explanation: {code} - {explain}.</p>
    </body>
</html>
"""

DEFAULT_ERROR_CONTENT_TYPE = "text/html;charset=utf-8"


class ProxyServerProtocol(asyncio.Protocol):
    error_message_format = DEFAULT_ERROR_MESSAGE
    error_content_type = DEFAULT_ERROR_CONTENT_TYPE

    def __init__(self, loop: AbstractEventLoop, key: str = None,
                 cert: str = None):
        self.loop: AbstractEventLoop = loop
        self.transport: Optional[transports.BaseTransport] = None
        self.proxy_connection: Optional[Tuple[str, int]] = None
        self.conn: h11.Connection = h11.Connection(h11.SERVER)

        self.ssl_proto: Optional[asyncio.sslproto.SSLProto] = None
        self.ssl_ctx: Optional[ssl.SSLContext] = None
        self.key: str = key
        self.cert: str = cert

        self.log: logging.Logger = logging.getLogger(__name__)
        self.log.setLevel(DEFAULT_LOG_LEVEL)

    def connection_made(self, transport: transports.BaseTransport) -> None:
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        if self.ssl_proto:
            self.ssl_proto.data_received(data)
        else:
            # print('IN: {}'.format(data))
            self.conn.receive_data(data)
            while True:
                event = self.conn.next_event()
                if isinstance(event, h11.Request):
                    if event.method == b'CONNECT':
                        self.do_CONNECT(event)
                    else:
                        self.do_VERB(event)
                elif event is h11.PAUSED:
                    self.conn.start_next_cycle()
                    continue
                elif isinstance(event, h11.ConnectionClosed) or event is h11.NEED_DATA:
                    break
            if self.conn.our_state is h11.MUST_CLOSE:
                self.transport.close()

    def do_CONNECT(self, event: h11.Request):
        req = ProxyRequest(event, self.conn)

        self.ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_ctx.load_cert_chain(self.cert, self.key)

        self.ssl_proto = asyncio.sslproto.SSLProtocol(self.loop, ProxyServerProtocol(self.loop),
                                                      self.ssl_ctx,
                                                      None,
                                                      server_side=True)

        self.ssl_proto.connection_made(self.transport)
        self.proxy_connection = (req.host, req.port)
        print('{} {}'.format(event.method.decode(), req.url), end='')

        response = h11.Response(status_code=HTTPStatus.OK, reason='Connection Established',
                                headers=[('Server', h11.PRODUCT_ID)])

        print(' - {} {}'.format(response.status_code, response.reason.decode()))

        self.send(response)
        self.conn = h11.Connection(h11.SERVER)

    def do_VERB(self, event: h11.Request):

        try:
            req = ProxyRequest(event, self.conn)
            url = req.url
            headers = req.headers
            print('{} {}'.format(req.method, url), end='')
            sys.stdout.flush()

            req_resp = requests.request(event.method, url, proxies=req.proxies, headers=headers,
                                        data=req.data)

            resp = ProxyRequest(req_resp, self.conn)
            print(' - {} {}'.format(resp.status, resp.reason))

            # self.log.info('{} {} - {}'.format(resp.status_code, resp.reason, url.decode()))

            headers = resp.headers
            content_encoding = headers.get('content-encoding', None)
            if content_encoding:
                if content_encoding == 'gzip':
                    resp.data = gzip.compress(resp.data)
                else:
                    self.log.warning('Unandled content-encoding {}'.format(content_encoding))
                    del headers['content-encoding']

            h11_resp = h11.Response(status_code=resp.status, reason=resp.reason,
                                    headers=resp.h11_headers)
            self.send(h11_resp)
            self.send(h11.Data(data=resp.data))
            self.send(h11.EndOfMessage())
        except Exception as e:
            self.log.error(repr(e))
            self.send_error(event, HTTPStatus.INTERNAL_SERVER_ERROR, explain=str(e))
            raise

    def send_error(self, event: h11.Request, status: HTTPStatus, msg: str = None, explain: str = None):
        try:
            short_msg, long_msg = responses[status]
        except KeyError:
            short_msg, long_msg = '???', '???'

        if msg is None:
            msg = short_msg

        if explain is None:
            explain = long_msg

        headers = []

        self.log.error('code {}, message {}'.format(status, msg))

        body = None
        if status >= 200 and status not in (HTTPStatus.NO_CONTENT, HTTPStatus.RESET_CONTENT, HTTPStatus.NOT_MODIFIED):
            body = self.error_message_format.format(code=status, message=msg, explain=explain).encode('UTF-8',
                                                                                                      'replace')
            headers.extend([('Content-Type', self.error_content_type),
                            ('Content-Length', str(len(body)))])

        headers.append(('Connection', 'close'))

        response = h11.Response(status_code=status, headers=headers)
        self.send(response)

        if event.method != 'HEAD' and body:
            self.send(h11.Data(data=body))

        self.send(h11.EndOfMessage())

    def send(self, event):
        data = self.conn.send(event)
        # print('OUT: {}'.format(data))
        self.transport.write(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Proxy Server using h11')
    parser.add_argument('-c', '--cert', default='proxy.crt')
    parser.add_argument('-k', '--key', default='proxy.key')

    args = parser.parse_args(argv)

    loop = asyncio.get_event_loop()
    coro = loop.create_server(lambda: ProxyServerProtocol(loop, key=args.key, cert=args.cert), '0.0.0.0', 8000)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('Cert: {} Key: {}'.format(args.cert, args.key))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
