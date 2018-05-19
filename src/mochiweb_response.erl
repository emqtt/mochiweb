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

%% @doc Response abstraction.

-module(mochiweb_response).
-author('bob@mochimedia.com').

-include("mochiweb.hrl").

-define(QUIP, "Any of you quaids got a smint?").

-export([new/3, get_header_value/2, get/2, dump/1]).
-export([send/2, write_chunk/2]).

%% @doc Create a new mochiweb_response instance.
%%-spec(new(request(), code(), headers()) -> response()).
new(Request, Code, Headers) ->
    {?MODULE, [Request, Code, Headers]}.

%% @doc Get the value of the given response header.
-spec(get_header_value(string() | atom() | binary(), response())
      -> string() | undefined).
get_header_value(Key, #response{headers = Headers}) ->
    mochiweb_headers:get_value(Key, Headers).

%% @doc Return the internal representation of the given field.
-spec(get(request | code | headers, response()) -> term()).
get(request, #response{request = Request}) ->
    Request;
get(code, #response{code = Code}) ->
    Code;
get(headers, #response{headers = Headers}) ->
    Headers.

%% @doc Dump the internal representation to a "human readable"
%%      set of terms for debugging/inspection purposes.
-spec(dump(response()) -> {mochiweb_request, [{atom(), term()}]}).
dump(#response{request = Request, code = Code, headers = Headers}) ->
    [{request, mochiweb_request:dump(Request)},
     {code, Code}, {headers, mochiweb_headers:to_list(Headers)}].

%% @spec send(iodata(), response()) -> ok
%% @doc Send data over the socket if the method is not HEAD.
send(Data, #response{request = Req}) ->
    case mochiweb_request:get(method, Req) of
        'HEAD' -> ok;
        _ -> mochiweb_request:send(Data, Req)
    end.

%% @doc Write a chunk of a HTTP chunked response. If Data is zero length,
%%      then the chunked response will be finished.
-spec(write_chunk(iodata(), response()) -> ok).
write_chunk(Data, Resp = #response{request = Req}) ->
    case mochiweb_request:get(version, Req) of
        Version when Version >= {1, 1} ->
            Length = iolist_size(Data),
            send([io_lib:format("~.16b\r\n", [Length]), Data, <<"\r\n">>], Resp);
        _ ->
            send(Data, Resp)
    end.

