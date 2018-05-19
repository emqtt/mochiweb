%% @author Bob Ippolito <bob@mochimedia.com>
%% @copyright 2007 Mochi Media, Inc.
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
%% THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

%% @doc Start and stop the MochiWeb server.

-module(mochiweb).

-include("mochiweb.hrl").

-author('bob@mochimedia.com').

-export([start_http/2, start_http/3, start_http/4]).
-export([stop_http/1, stop_http/2]).
-export([restart_http/1, restart_http/2]).
-export([new_request/1, new_response/1]).

-define(SOCKET_OPTS, [binary,
                      {reuseaddr, true},
                      {packet, raw},
                      {backlog, 1024},
                      {recbuf, ?RECBUF_SIZE},
                      {send_timeout, 15000},
                      {send_timeout_close, true},
                      {exit_on_close, false},
                      {nodelay, false}]).

%% @doc Start HTTP Listener
-spec(start_http(esockd:listen_on(), esockd:mfargs()) -> {ok, pid()}).
start_http(ListenOn, MFArgs) ->
    start_http(ListenOn, [], MFArgs).

-spec(start_http(esockd:listen_on(), [esockd:option()], esockd:mfargs())
      -> {ok, pid()} | {error, term()}).
start_http(ListenOn, Options, MFArgs) ->
    start_http(http, ListenOn, Options, MFArgs).

-spec(start_http(atom(), esockd:listen_on(), [esockd:option()], esockd:mfargs())
      -> {ok, pid()} | {error, term()}).
start_http(Proto, ListenOn, Options, MFArgs) when is_atom(Proto) ->
    SockOpts = merge_opts(?SOCKET_OPTS,
                          proplists:get_value(sockopts, Options, [])),
    esockd:open(Proto, ListenOn, merge_opts(Options, [{sockopts, SockOpts}]),
                {mochiweb_http, start_link, [MFArgs]}).

%% @doc Stop HTTP Listener
-spec(stop_http(esockd:listen_on()) -> ok).
stop_http(ListenOn) ->
    stop_http(http, ListenOn).

-spec(stop_http(atom(), esockd:listen_on()) -> ok).
stop_http(Proto, ListenOn) ->
    esockd:close(Proto, ListenOn).

%% @doc Restart HTTP Listener
-spec(restart_http(esockd:listen_on())
      -> {ok, pid()} | {error, term()}).
restart_http(ListenOn) ->
    restart_http(http, ListenOn).

-spec(restart_http(atom(), esockd:listen_on())
      -> {ok, pid()} | {error, term()}).
restart_http(Proto, ListenOn) ->
    esockd:reopen(Proto, ListenOn).

%% @private
merge_opts(Defaults, Options) ->
    lists:foldl(
      fun({Opt, Val}, Acc) ->
          lists:keystore(Opt, 1, Acc, {Opt, Val});
         (Opt, Acc) ->
          lists:usort([Opt | Acc])
      end, Defaults, Options).

%% See the erlang:decode_packet/3 docs for the full type
-spec uri(HttpUri :: term()) -> string().
uri({abs_path, Uri}) ->
    Uri;
%% TODO:
%% This makes it hard to implement certain kinds of proxies with mochiweb,
%% perhaps a field could be added to the mochiweb_request record to preserve
%% this information in raw_path.
uri({absoluteURI, _Protocol, _Host, _Port, Uri}) ->
    Uri;
%% From http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
uri('*') ->
    "*";
%% Erlang decode_packet will return this for requests like `CONNECT host:port`
uri({scheme, Hostname, Port}) ->
    Hostname ++ ":" ++ Port;
uri(HttpString) when is_list(HttpString) ->
    HttpString.

%% @spec new_request({Transport, Sock, Request, Headers}) -> MochiWebRequest
%% @doc Return a mochiweb_request data structure.
new_request({Transport, Sock, {Method, HttpUri, Version}, Headers}) ->
    mochiweb_request:new(Transport,
                         Sock,
                         Method,
                         uri(HttpUri),
                         Version,
                         mochiweb_headers:make(Headers)).

%% @spec new_response({Request, integer(), Headers}) -> MochiWebResponse
%% @doc Return a mochiweb_response data structure.
new_response({Request, Code, Headers}) ->
    mochiweb_response:new(Request,
                          Code,
                          mochiweb_headers:make(Headers)).

