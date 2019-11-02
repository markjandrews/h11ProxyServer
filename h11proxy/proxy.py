import asyncio
import logging
import ssl
from asyncio import transports
from http import HTTPStatus

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

    def __init__(self, loop, req: ProxyRequest = None):
        self.log: logging.Logger = logging.getLogger(__name__)
        self.log.setLevel(DEFAULT_LOG_LEVEL)
        self.loop = loop
        self.req = req if req else ProxyRequest()
        self.transport = None
        self.ssl_ctx = None
        self.ssl_proto: asyncio.sslproto.SSLProto = None

    def connection_made(self, transport: transports.BaseTransport) -> None:
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        if self.ssl_proto:
            self.ssl_proto.data_received(data)
        else:
            print('IN: {}'.format(data))
            self.req.conn.receive_data(data)
            while True:
                event = self.req.conn.next_event()
                if isinstance(event, h11.Request):
                    if event.method == b'CONNECT':
                        self.do_CONNECT(event)
                    else:
                        self.do_VERB(event)
                elif event is h11.PAUSED:
                    self.req.conn.start_next_cycle()
                    continue
                elif isinstance(event, h11.ConnectionClosed) or event is h11.NEED_DATA:
                    break
            if self.req.conn.our_state is h11.MUST_CLOSE:
                self.transport.close()

    def do_CONNECT(self, event: h11.Request):
        self.req.host, self.req.port = event.target.split(b':')
        self.req.scheme = 'https'

        self.ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_ctx.load_cert_chain('proxy.crt', 'proxy.key')

        self.ssl_proto = asyncio.sslproto.SSLProtocol(self.loop, ProxyServerProtocol(self.loop, self.req), self.ssl_ctx,
                                                      None,
                                                      server_side=True)

        self.ssl_proto.connection_made(self.transport)

        response = h11.Response(status_code=HTTPStatus.OK, reason='Connection Established',
                                headers=[('Server', h11.PRODUCT_ID)])
        self.send(response)
        self.req.conn = h11.Connection(h11.SERVER)

    def do_VERB(self, event: h11.Request):

        url = self.req.get_url(event)
        headers = self.req.get_h11_headers(event)

        if b'content-length' in headers:
            data_event = self.req.conn.next_event()
            assert isinstance(data_event, h11.Data)
            data = data_event.data
        else:
            data = None

        resp = requests.request(event.method, url, proxies=self.req.proxies, headers=headers, data=data)
        # self.log.info('{} {} - {}'.format(resp.status_code, resp.reason, url.decode()))

        if 'content-encoding' in resp.headers:
            del resp.headers['content-encoding']

        headers = self.req.get_requests_headers(resp)
        h11_resp = h11.Response(status_code=resp.status_code, reason=resp.reason, headers=headers)
        self.send(h11_resp)
        self.send(h11.Data(data=resp.content))
        self.send(h11.EndOfMessage())

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
        data = self.req.conn.send(event)
        print('OUT: {}'.format(data))
        self.transport.write(data)


def main(argv=None):
    loop = asyncio.get_event_loop()
    coro = loop.create_server(lambda: ProxyServerProtocol(loop), '0.0.0.0', 8000)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
