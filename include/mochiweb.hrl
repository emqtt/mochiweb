
-define(RECBUF_SIZE, 8192).

-type(method() :: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'DELETE' |
                  'CONNECT' | 'OPTIONS' | 'PATCH' | 'TRACE').

-record(request, {transport, sock, method, rawpath, version, headers}).

-type(request() :: #request{}).

-record(response, {request, code, headers}).

-type(response() :: #response{}).

