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

%% @doc MochiWeb HTTP Request abstraction.

-module(mochiweb_request).
-author('bob@mochimedia.com').

-include("mochiweb.hrl").
-include_lib("kernel/include/file.hrl").

-define(QUIP, "Any of you quaids got a smint?").

-export([new/6]).
-export([get_header_value/2, get_primary_header_value/2, get_combined_header_value/2, get/2]).
-export([dump/1]).
-export([send/2, recv/2, recv/3, recv_body/1, recv_body/2, stream_body/4]).
-export([start_response/2, start_response_length/2, start_raw_response/2]).
-export([respond/2, ok/2]).
-export([not_found/1, not_found/2]).
-export([parse_post/1, parse_qs/1]).
-export([should_close/1, cleanup/1]).
-export([parse_cookie/1, get_cookie_value/2]).
-export([serve_file/3, serve_file/4]).
-export([accepted_encodings/2]).
-export([accepts_content_type/2, accepted_content_types/2]).

-define(SAVE_QS, mochiweb_request_qs).
-define(SAVE_PATH, mochiweb_request_path).
-define(SAVE_RECV, mochiweb_request_recv).
-define(SAVE_BODY, mochiweb_request_body).
-define(SAVE_BODY_LENGTH, mochiweb_request_body_length).
-define(SAVE_POST, mochiweb_request_post).
-define(SAVE_COOKIE, mochiweb_request_cookie).
-define(SAVE_FORCE_CLOSE, mochiweb_request_force_close).

% 1 minute default idle timeout
-define(IDLE_TIMEOUT, 60000).
% Maximum recv_body() length of 1MB
-define(MAX_RECV_BODY, (1024*1024)).

-type(version() :: {non_neg_integer(), non_neg_integer()}).
-type(path() :: string()).
-type(encoding() :: string()).
-type(key() :: atom() | string() | binary()).
-type(value() :: atom() | string() | binary() | integer()).
-type(headers() :: [{key(), value()}]).
-type(ioheaders() :: headers() | [{key(), value()}]).
-type(field() :: socket | scheme | method | raw_path | version |
                 headers | peername | path | body_length | range).

%% @doc Create a new request instance.
-spec(new(esockd:transport(), esockd:sock(), method(),
          string(), version(), headers()) -> request()).
new(Transport, Sock, Method, RawPath, Version, Headers) ->
    #request{transport = Transport, sock = Sock, method = Method,
             rawpath = RawPath, version = Version, headers = Headers}.

%% @doc Get the value of a given request header.
-spec(get_header_value(key(), request()) -> undefined | value()).
get_header_value(Key, #request{headers = Headers}) ->
    mochiweb_headers:get_value(Key, Headers).

get_primary_header_value(Key, #request{headers = Headers}) ->
    mochiweb_headers:get_primary_value(Key, Headers).

get_combined_header_value(K, #request{headers = Headers}) ->
    mochiweb_headers:get_combined_value(K, Headers).

%% @doc Return the internal representation of the given field.
-spec(get(field(), request()) -> term()).
get(transport, #request{transport = Transport}) ->
    Transport;
get(socket, #request{sock = Sock}) ->
    Sock;
get(scheme, #request{transport = Transport, sock = Sock}) ->
    case Transport:is_ssl(Sock) of
        false -> http;
        true  -> https
    end;
get(method, #request{method = Method}) ->
    Method;
get(raw_path, #request{rawpath = RawPath}) ->
    RawPath;
get(version, #request{version = Version}) ->
    Version;
get(headers, #request{headers = Headers}) ->
    Headers;
get(peername, #request{transport = Transport, sock = Sock}) ->
    Transport:peername(Sock);
get(path, #request{rawpath = RawPath}) ->
    case erlang:get(?SAVE_PATH) of
        undefined ->
            {Path0, _, _} = mochiweb_util:urlsplit_path(RawPath),
            Path = mochiweb_util:normalize_path(mochiweb_util:unquote(Path0)),
            put(?SAVE_PATH, Path),
            Path;
        Cached -> Cached
    end;
get(body_length, Req) ->
    case erlang:get(?SAVE_BODY_LENGTH) of
        undefined ->
            BodyLength = body_length(Req),
            put(?SAVE_BODY_LENGTH, {cached, BodyLength}),
            BodyLength;
        {cached, Cached} ->
            Cached
    end;
get(range, Req) ->
    case get_header_value(range, Req) of
        undefined -> undefined;
        RawRange  ->
            mochiweb_http:parse_range_request(RawRange)
    end.

%% @doc Dump the internal representation to a "human readable" set of terms
%%      for debugging/inspection purposes.
-spec(dump(request()) -> {request, [{atom(), term()}]}).
dump(#request{method = Method, rawpath = RawPath,
              version = Version, headers = Headers}) ->
    {request, [{method,   Method},
               {version,  Version},
               {raw_path, RawPath},
               {headers,  mochiweb_headers:to_list(Headers)}]}.

%% @doc Send data over the socket.
-spec(send(iodata(), request()) -> ok).
send(Data, #request{transport = Transport, sock = Sock}) ->
    case Transport:send(Sock, Data) of
        ok -> ok;
        {error, Reason} ->
            Transport:fast_close(Sock),
            exit({shutdown, Reason})
    end.

%% @doc Receive Length bytes from the client as a binary,
%%      with the default idle timeout.
-spec(recv(integer(), request()) -> binary()).
recv(Length, Req) ->
    recv(Length, ?IDLE_TIMEOUT, Req).

%% @doc Receive Length bytes from the client as a binary,
%%     with the given timeout in msec.
-spec(recv(integer(), integer(), request()) -> binary()).
recv(Length, Timeout, Req = #request{transport = Transport, sock = Sock}) ->
    case Transport:recv(Sock, Length, Timeout) of
        {ok, Data} ->
            put(?SAVE_RECV, true),
            Data;
        {error, _Reason} ->
            stop(normal, Req)
    end.

%% @doc Infer body length from transfer-encoding and content-length headers.
-spec(body_length(request()) -> undefined | chunked |
                                unknown_transfer_encoding | integer()).
body_length(Req) ->
    case get_header_value("transfer-encoding", Req) of
        undefined ->
            case get_combined_header_value("content-length", Req) of
                undefined ->
                    undefined;
                Length ->
                    list_to_integer(Length)
            end;
        "chunked" ->
            chunked;
        Unknown ->
            {unknown_transfer_encoding, Unknown}
    end.

%% @doc Receive the body of the HTTP request (defined by Content-Length).
%%      Will only receive up to the default max-body length of 1MB.
-spec(recv_body(request()) -> binary()).
recv_body(Req) ->
    recv_body(?MAX_RECV_BODY, Req).

%% @doc Receive the body of the HTTP request (defined by Content-Length).
%%      Will receive up to MaxBody bytes.
-spec(recv_body(integer(), request()) -> binary()).
recv_body(MaxBody, Req) ->
    case erlang:get(?SAVE_BODY) of
        undefined ->
            % we could use a sane constant for max chunk size
            Body = stream_body(?MAX_RECV_BODY, fun
                ({0, _ChunkedFooter}, {_LengthAcc, BinAcc}) ->
                    iolist_to_binary(lists:reverse(BinAcc));
                ({Length, Bin}, {LengthAcc, BinAcc}) ->
                    NewLength = Length + LengthAcc,
                    if NewLength > MaxBody ->
                        exit({body_too_large, chunked});
                    true ->
                        {NewLength, [Bin | BinAcc]}
                    end
                end, {0, []}, MaxBody, Req),
            put(?SAVE_BODY, Body),
            Body;
        Cached -> Cached
    end.

stream_body(MaxChunkSize, ChunkFun, FunState, Req) ->
    stream_body(MaxChunkSize, ChunkFun, FunState, undefined, Req).

stream_body(MaxChunkSize, ChunkFun, FunState, MaxBodyLength, Req) ->
    Expect = case get_header_value("expect", Req) of
                 undefined ->
                     undefined;
                 Value when is_list(Value) ->
                     string:to_lower(Value)
             end,
    case Expect of
        "100-continue" ->
            _ = start_raw_response({100, gb_trees:empty()}, Req),
            ok;
        _Else -> ok
    end,
    case body_length(Req) of
        undefined ->
            undefined;
        {unknown_transfer_encoding, Unknown} ->
            exit({unknown_transfer_encoding, Unknown});
        chunked ->
            % In this case the MaxBody is actually used to
            % determine the maximum allowed size of a single
            % chunk.
            stream_chunked_body(MaxChunkSize, ChunkFun, FunState, Req);
        0 ->
            <<>>;
        Length when is_integer(Length) ->
            case MaxBodyLength of
            MaxBodyLength when is_integer(MaxBodyLength), MaxBodyLength < Length ->
                exit({body_too_large, content_length});
            _ ->
                stream_unchunked_body(MaxChunkSize,Length, ChunkFun, FunState, Req)
            end
    end.

%% @doc Start the HTTP response by sending the Code HTTP response and
%%      ResponseHeaders. The server will set header defaults such as Server
%%      and Date if not present in ResponseHeaders.
-spec(start_response({integer(), ioheaders()}, request()) -> response()).
start_response({Code, ResponseHeaders}, Req) ->
    start_raw_response({Code, ResponseHeaders}, Req).

%% @doc Start the HTTP response by sending the Code HTTP response and
%%      ResponseHeaders.
-spec(start_raw_response({integer(), headers()}, request()) -> response()).
start_raw_response({Code, ResponseHeaders}, Req) ->
    {Header, Response} = format_response_header({Code, ResponseHeaders}, Req),
    send(Header, Req),
    Response.

%% @doc Start the HTTP response by sending the Code HTTP response and
%%      ResponseHeaders including a Content-Length of Length. The server
%%      will set header defaults such as Server
%%      and Date if not present in ResponseHeaders.
-spec(start_response_length({integer(), ioheaders(), integer()}, request()) -> response()).
start_response_length({Code, ResponseHeaders, Length}, Req) ->
    HResponse = mochiweb_headers:make(ResponseHeaders),
    HResponse1 = mochiweb_headers:enter("Content-Length", Length, HResponse),
    start_response({Code, HResponse1}, Req).

%% @doc Format the HTTP response header, including the Code HTTP response and
%%      ResponseHeaders including an optional Content-Length of Length. The server
%%      will set header defaults such as Server
%%      and Date if not present in ResponseHeaders.
-spec(format_response_header({integer(), ioheaders()} | {integer(), ioheaders(), integer()}, request())
      -> iolist()).
format_response_header({Code, ResponseHeaders}, Req = #request{version = Version}) ->
    HResponse = mochiweb_headers:make(ResponseHeaders),
    HResponse1 = mochiweb_headers:default_from_list(server_headers(), HResponse),
    HResponse2 = case should_close(Req) of
                     true  -> mochiweb_headers:enter("Connection", "close", HResponse1);
                     false -> HResponse1
                 end,
    End = [[mochiweb_util:make_io(K), <<": ">>, V, <<"\r\n">>]
           || {K, V} <- mochiweb_headers:to_list(HResponse2)],
    Response = mochiweb:new_response({Req, Code, HResponse2}),
    {[make_version(Version), make_code(Code), <<"\r\n">> | [End, <<"\r\n">>]], Response};
format_response_header({Code, ResponseHeaders, Length}, Req) ->
    HResponse = mochiweb_headers:make(ResponseHeaders),
    HResponse1 = mochiweb_headers:enter("Content-Length", Length, HResponse),
    format_response_header({Code, HResponse1}, Req).

%% @doc Start the HTTP response with start_response, and send Body to the
%%      client (if the get(method) /= 'HEAD'). The Content-Length header
%%      will be set by the Body length, and the server will insert header
%%      defaults.
-spec(respond({integer(), ioheaders(), iodata() | chunked | {file, io:device()}},
              request()) -> response()).
respond({Code, ResponseHeaders, {file, IoDevice}}, Req = #request{method = Method}) ->
    Length = mochiweb_io:iodevice_size(IoDevice),
    Response = start_response_length({Code, ResponseHeaders, Length}, Req),
    case Method of
        'HEAD' -> ok;
        _Other -> mochiweb_io:iodevice_stream(
                    fun (Body) -> send(Body, Req) end,
                  IoDevice)
    end,
    Response;
respond({Code, ResponseHeaders, chunked}, Req = #request{method = Method, version = Version}) ->
    HResponse = mochiweb_headers:make(ResponseHeaders),
    HResponse1 = case Method of
                     'HEAD' ->
                         %% This is what Google does, http://www.google.com/
                         %% is chunked but HEAD gets Content-Length: 0.
                         %% The RFC is ambiguous so emulating Google is smart.
                         mochiweb_headers:enter("Content-Length", "0",
                                                HResponse);
                     _ when Version >= {1, 1} ->
                         %% Only use chunked encoding for HTTP/1.1
                         mochiweb_headers:enter("Transfer-Encoding", "chunked",
                                                HResponse);
                     _ ->
                         %% For pre-1.1 clients we send the data as-is
                         %% without a Content-Length header and without
                         %% chunk delimiters. Since the end of the document
                         %% is now ambiguous we must force a close.
                         put(?SAVE_FORCE_CLOSE, true),
                         HResponse
                 end,
    start_response({Code, HResponse1}, Req);
respond({Code, ResponseHeaders, Body}, Req = #request{method = Method}) ->
    {Header, Response} = format_response_header(
                           {Code, ResponseHeaders, iolist_size(Body)}, Req),
    case Method of
        'HEAD' -> send(Header, Req);
        _      -> send([Header, Body], Req)
    end,
    Response.

%% @doc Alias for <code>not_found([])</code>.
-spec(not_found(request()) -> response()).
not_found(Req) ->
    not_found([], Req).

%% @doc Alias for <code>respond({404, [{"Content-Type", "text/plain"}
%% | ExtraHeaders], &lt;&lt;"Not found."&gt;&gt;})</code>.
-spec(not_found(headers(), request()) -> response()).
not_found(ExtraHeaders, Req) ->
    respond({404, [{"Content-Type", "text/plain"} | ExtraHeaders], <<"Not found.">>}, Req).

%% @doc respond({200, [{"Content-Type", ContentType} | Headers], Body}).
-spec(ok({value(), iodata()} | {value(), ioheaders(), iodata() | {file, io:device()}},
         request()) -> response()).
ok({ContentType, Body}, Req) ->
    ok({ContentType, [], Body}, Req);
ok({ContentType, ResponseHeaders, Body}, Req) ->
    HResponse = mochiweb_headers:make(ResponseHeaders),
    case get(range, Req) of
        X when (X =:= undefined orelse X =:= fail) orelse Body =:= chunked ->
            %% http://code.google.com/p/mochiweb/issues/detail?id=54
            %% Range header not supported when chunked, return 200 and provide
            %% full response.
            HResponse1 = mochiweb_headers:enter("Content-Type", ContentType,
                                                HResponse),
            respond({200, HResponse1, Body}, Req);
        Ranges ->
            {PartList, Size} = range_parts(Body, Ranges),
            case PartList of
                [] -> %% no valid ranges
                    HResponse1 = mochiweb_headers:enter("Content-Type",
                                                        ContentType,
                                                        HResponse),
                    %% could be 416, for now we'll just return 200
                    respond({200, HResponse1, Body}, Req);
                PartList ->
                    {RangeHeaders, RangeBody} =
                        mochiweb_multipart:parts_to_body(PartList, ContentType, Size),
                    HResponse1 = mochiweb_headers:enter_from_list(
                                   [{"Accept-Ranges", "bytes"} |
                                    RangeHeaders],
                                   HResponse),
                    respond({206, HResponse1, RangeBody}, Req)
            end
    end.

%% @doc Return true if the connection must be closed. If false, using
%%      Keep-Alive should be safe.
-spec(should_close(request()) -> boolean()).
should_close(Req = #request{version = Version}) ->
    ForceClose = erlang:get(?SAVE_FORCE_CLOSE) =/= undefined,
    DidNotRecv = erlang:get(?SAVE_RECV) =:= undefined,
    ForceClose orelse Version < {1, 0}
        %% Connection: close
        orelse is_close(get_header_value("connection", Req))
        %% HTTP 1.0 requires Connection: Keep-Alive
        orelse (Version =:= {1, 0}
                andalso get_header_value("connection", Req) =/= "Keep-Alive")
        %% unread data left on the socket, can't safely continue
        orelse (DidNotRecv
                andalso get_combined_header_value("content-length", Req) =/= undefined
                andalso list_to_integer(get_combined_header_value("content-length", Req)) > 0)
        orelse (DidNotRecv
                andalso get_header_value("transfer-encoding", Req) =:= "chunked").

is_close("close") ->
    true;
is_close(S=[_C, _L, _O, _S, _E]) ->
    string:to_lower(S) =:= "close";
is_close(_) ->
    false.

%% @doc Clean up any junk in the process dictionary, required before continuing
%%      a Keep-Alive request.
-spec(cleanup(request()) -> ok).
cleanup(_Req) ->
    L = [?SAVE_QS, ?SAVE_PATH, ?SAVE_RECV, ?SAVE_BODY, ?SAVE_BODY_LENGTH,
         ?SAVE_POST, ?SAVE_COOKIE, ?SAVE_FORCE_CLOSE],
    lists:foreach(fun(K) ->
                          erase(K)
                  end, L),
    ok.

%% @doc Parse the query string of the URL.
-spec(parse_qs(request()) -> [{Key::string(), Value::string()}]).
parse_qs(#request{rawpath = RawPath}) ->
    case erlang:get(?SAVE_QS) of
        undefined ->
            {_, QueryString, _} = mochiweb_util:urlsplit_path(RawPath),
            Parsed = mochiweb_util:parse_qs(QueryString),
            put(?SAVE_QS, Parsed),
            Parsed;
        Cached -> Cached
    end.

%% @doc Get the value of the given cookie.
-spec(get_cookie_value(Key::string, request()) -> string() | undefined).
get_cookie_value(Key, Req) ->
    proplists:get_value(Key, parse_cookie(Req)).

%% @doc Parse the cookie header.
-spec(parse_cookie(request()) -> [{Key::string(), Value::string()}]).
parse_cookie(Req) ->
    case erlang:get(?SAVE_COOKIE) of
        undefined ->
            Cookies = case get_header_value("cookie", Req) of
                          undefined ->
                              [];
                          Value ->
                              mochiweb_cookies:parse_cookie(Value)
                      end,
            put(?SAVE_COOKIE, Cookies),
            Cookies;
        Cached ->
            Cached
    end.

%% @doc Parse an application/x-www-form-urlencoded form POST. This
%%      has the side-effect of calling recv_body().
-spec(parse_post(request()) -> [{Key::string(), Value::string()}]).
parse_post(Req) ->
    case erlang:get(?SAVE_POST) of
        undefined ->
            Parsed = case recv_body(Req) of
                         undefined ->
                             [];
                         Binary ->
                             case get_primary_header_value("content-type",Req) of
                                 "application/x-www-form-urlencoded" ++ _ ->
                                     mochiweb_util:parse_qs(Binary);
                                 "application/json" ++ _ -> %% TODO:???
                                     {struct, Json} = mochijson2:decode(Binary),
                                     Json;
                                 _ ->
                                     []
                             end
                     end,
            put(?SAVE_POST, Parsed),
            Parsed;
        Cached ->
            Cached
    end.

%% @doc The function is called for each chunk.
%%      Used internally by read_chunked_body.
-spec(stream_chunked_body(integer(), fun(), term(), request()) -> term()).
stream_chunked_body(MaxChunkSize, Fun, FunState, Req) ->
    case read_chunk_length(Req) of
        0 ->
            Fun({0, read_chunk(0, Req)}, FunState);
        Length when Length > MaxChunkSize ->
            NewState = read_sub_chunks(Length, MaxChunkSize, Fun, FunState, Req),
            stream_chunked_body(MaxChunkSize, Fun, NewState, Req);
        Length ->
            NewState = Fun({Length, read_chunk(Length, Req)}, FunState),
            stream_chunked_body(MaxChunkSize, Fun, NewState, Req)
    end.

stream_unchunked_body(_MaxChunkSize, 0, Fun, FunState, _Req) ->
    Fun({0, <<>>}, FunState);
stream_unchunked_body(MaxChunkSize, Length, Fun, FunState,
                      Req = #request{transport = Transport, sock = Sock}) when Length > 0 ->
    {ok, Opts} = mochiweb_util:exit_if_closed(
                   Transport:getopts(Sock, [recbuf])),
    RecBuf = case mochilists:get_value(recbuf, Opts, ?RECBUF_SIZE) of
        undefined -> %os controlled buffer size
            MaxChunkSize;
        Val  ->
            Val
    end,
    PktSize=min(Length,RecBuf),
    Bin = recv(PktSize, Req),
    NewState = Fun({PktSize, Bin}, FunState),
    stream_unchunked_body(MaxChunkSize, Length - PktSize, Fun, NewState, Req).

%% @doc Read the length of the next HTTP chunk.
-spec(read_chunk_length(request()) -> integer()).
read_chunk_length(#request{transport = Transport, sock = Sock}) ->
    ok = mochiweb_util:exit_if_closed(
           Transport:setopts(Sock, [{packet, line}])),
    case Transport:recv(Sock, 0, ?IDLE_TIMEOUT) of
        {ok, Header} ->
            ok = mochiweb_util:exit_if_closed(
                   Transport:setopts(Sock, [{packet, raw}])),
            Splitter = fun (C) ->
                           C =/= $\r andalso C =/= $\n andalso C =/= $
                       end,
            {Hex, _Rest} = lists:splitwith(Splitter, binary_to_list(Header)),
            mochihex:to_int(Hex);
        _ ->
            Transport:fast_close(Sock),
            exit(normal)
    end.

%% @doc Read in a HTTP chunk of the given length. If Length is 0, then read the
%%      HTTP footers (as a list of binaries, since they're nominal).
-spec(read_chunk(integer(), request()) -> Chunk::binary() | [Footer::binary()]).
read_chunk(0, #request{transport = Transport, sock = Sock}) ->
    ok = mochiweb_util:exit_if_closed(
           Transport:setopts(Sock, [{packet, line}])),
    F = fun (F1, Acc) ->
                case Transport:recv(Sock, 0, ?IDLE_TIMEOUT) of
                    {ok, <<"\r\n">>} ->
                        Acc;
                    {ok, Footer} ->
                        F1(F1, [Footer | Acc]);
                    _ ->
                        exit(normal)
                end
        end,
    Footers = F(F, []),
    ok = Transport:setopts(Sock, [{packet, raw}]),
    put(?SAVE_RECV, true),
    Footers;
read_chunk(Length, #request{transport = Transport, sock = Sock}) ->
    case mochiweb_util:exit_if_closed(
           Transport:recv(Sock, 2 + Length, ?IDLE_TIMEOUT)) of
        {ok, <<Chunk:Length/binary, "\r\n">>} ->
            Chunk;
        _ ->
            Transport:fast_close(Sock),
            exit(normal)
    end.

read_sub_chunks(Length, MaxChunkSize, Fun, FunState, Req) when Length > MaxChunkSize ->
    Bin = recv(MaxChunkSize, Req),
    NewState = Fun({size(Bin), Bin}, FunState),
    read_sub_chunks(Length - MaxChunkSize, MaxChunkSize, Fun, NewState, Req);

read_sub_chunks(Length, _MaxChunkSize, Fun, FunState, Req) ->
    Fun({Length, read_chunk(Length, Req)}, FunState).

%% @doc Serve a file relative to DocRoot.
-spec(serve_file(path(), string(), request()) -> response()).
serve_file(Path, DocRoot, Req) ->
    serve_file(Path, DocRoot, [], Req).

%% @doc Serve a file relative to DocRoot.
-spec(serve_file(path(), string(), headers(), request())
      -> response()).
serve_file(Path, DocRoot, ExtraHeaders, Req) ->
    case mochiweb_util:safe_relative_path(Path) of
        undefined ->
            not_found(ExtraHeaders, Req);
        RelPath ->
            FullPath = filename:join([DocRoot, RelPath]),
            case filelib:is_dir(FullPath) of
                true ->
                    maybe_redirect(RelPath, FullPath, ExtraHeaders, Req);
                false ->
                    maybe_serve_file(FullPath, ExtraHeaders, Req)
            end
    end.

%% Internal API

%% This has the same effect as the DirectoryIndex directive in httpd
directory_index(FullPath) ->
    filename:join([FullPath, "index.html"]).

maybe_redirect([], FullPath, ExtraHeaders, Req) ->
    maybe_serve_file(directory_index(FullPath), ExtraHeaders, Req);

maybe_redirect(RelPath, FullPath, ExtraHeaders,
               Req = #request{headers =  Headers}) ->
    case string:right(RelPath, 1) of
        "/" ->
            maybe_serve_file(directory_index(FullPath), ExtraHeaders, Req);
        _   ->
            Host = mochiweb_headers:get_value("host", Headers),
            Location = "http://" ++ Host  ++ "/" ++ RelPath ++ "/",
            LocationBin = list_to_binary(Location),
            MoreHeaders = [{"Location", Location},
                           {"Content-Type", "text/html"} | ExtraHeaders],
            Top = <<"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
            "<html><head>"
            "<title>301 Moved Permanently</title>"
            "</head><body>"
            "<h1>Moved Permanently</h1>"
            "<p>The document has moved <a href=\"">>,
            Bottom = <<">here</a>.</p></body></html>\n">>,
            Body = <<Top/binary, LocationBin/binary, Bottom/binary>>,
            respond({301, MoreHeaders, Body}, Req)
    end.

maybe_serve_file(File, ExtraHeaders, Req) ->
    case file:read_file_info(File) of
        {ok, FileInfo} ->
            LastModified = httpd_util:rfc1123_date(FileInfo#file_info.mtime),
            case get_header_value("if-modified-since", Req) of
                LastModified ->
                    respond({304, ExtraHeaders, ""}, Req);
                _ ->
                    case file:open(File, [raw, binary]) of
                        {ok, IoDevice} ->
                            ContentType = mochiweb_util:guess_mime(File),
                            Res = ok({ContentType,
                                      [{"last-modified", LastModified}
                                       | ExtraHeaders],
                                      {file, IoDevice}}, Req),
                            ok = file:close(IoDevice),
                            Res;
                        _ ->
                            not_found(ExtraHeaders, Req)
                    end
            end;
        {error, _} ->
            not_found(ExtraHeaders, Req)
    end.

server_headers() ->
    [{"Server", "MochiWeb/1.0 (" ++ ?QUIP ++ ")"},
     {"Date", httpd_util:rfc1123_date()}].

make_code(X) when is_integer(X) ->
    [integer_to_list(X), [" " | httpd_util:reason_phrase(X)]];
make_code(Io) when is_list(Io); is_binary(Io) ->
    Io.

make_version({1, 0}) ->
    <<"HTTP/1.0 ">>;
make_version(_) ->
    <<"HTTP/1.1 ">>.

range_parts({file, IoDevice}, Ranges) ->
    Size = mochiweb_io:iodevice_size(IoDevice),
    F = fun (Spec, Acc) ->
                case mochiweb_http:range_skip_length(Spec, Size) of
                    invalid_range ->
                        Acc;
                    V ->
                        [V | Acc]
                end
        end,
    LocNums = lists:foldr(F, [], Ranges),
    {ok, Data} = file:pread(IoDevice, LocNums),
    Bodies = lists:zipwith(fun ({Skip, Length}, PartialBody) ->
                                   case Length of
                                       0 ->
                                           {Skip, Skip, <<>>};
                                       _ ->
                                           {Skip, Skip + Length - 1, PartialBody}
                                   end
                           end,
                           LocNums, Data),
    {Bodies, Size};
range_parts(Body0, Ranges) ->
    Body = iolist_to_binary(Body0),
    Size = size(Body),
    F = fun(Spec, Acc) ->
                case mochiweb_http:range_skip_length(Spec, Size) of
                    invalid_range ->
                        Acc;
                    {Skip, Length} ->
                        <<_:Skip/binary, PartialBody:Length/binary, _/binary>> = Body,
                        [{Skip, Skip + Length - 1, PartialBody} | Acc]
                end
        end,
    {lists:foldr(F, [], Ranges), Size}.

%% @doc Returns a list of encodings accepted by a request. Encodings that are
%%      not supported by the server will not be included in the return list.
%%      This list is computed from the "Accept-Encoding" header and
%%      its elements are ordered, descendingly, according to their Q values.
%%
%%      Section 14.3 of the RFC 2616 (HTTP 1.1) describes the "Accept-Encoding"
%%      header and the process of determining which server supported encodings
%%      can be used for encoding the body for the request's response.
%%
%%      Examples
%%
%%      1) For a missing "Accept-Encoding" header:
%%         accepted_encodings(["gzip", "identity"]) -> ["identity"]
%%
%%      2) For an "Accept-Encoding" header with value "gzip, deflate":
%%         accepted_encodings(["gzip", "identity"]) -> ["gzip", "identity"]
%%
%%      3) For an "Accept-Encoding" header with value "gzip;q=0.5, deflate":
%%         accepted_encodings(["gzip", "deflate", "identity"]) ->
%%            ["deflate", "gzip", "identity"]
%%
-spec(accepted_encodings([encoding()], request()) -> [encoding()] | bad_accept_encoding_value).
accepted_encodings(SupportedEncodings, Req) ->
    AcceptEncodingHeader = case get_header_value("Accept-Encoding", Req) of
        undefined -> "";
        Value     -> Value
    end,
    case mochiweb_util:parse_qvalues(AcceptEncodingHeader) of
        invalid_qvalue_string ->
            bad_accept_encoding_value;
        QList ->
            mochiweb_util:pick_accepted_encodings(QList, SupportedEncodings, "identity")
    end.

%% @doc Determines whether a request accepts a given media type by analyzing its
%%      "Accept" header.
%%
%%      Examples
%%
%%      1) For a missing "Accept" header:
%%         accepts_content_type("application/json") -> true
%%
%%      2) For an "Accept" header with value "text/plain, application/*":
%%         accepts_content_type("application/json") -> true
%%
%%      3) For an "Accept" header with value "text/plain, */*; q=0.0":
%%         accepts_content_type("application/json") -> false
%%
%%      4) For an "Accept" header with value "text/plain; q=0.5, */*; q=0.1":
%%         accepts_content_type("application/json") -> true
%%
%%      5) For an "Accept" header with value "text/*; q=0.0, */*":
%%         accepts_content_type("text/plain") -> false
%%
-spec(accepts_content_type(string() | binary(), request()) -> boolean() | bad_accept_header).
accepts_content_type(ContentType1, Req) ->
    ContentType = re:replace(ContentType1, "\\s", "", [global, {return, list}]),
    AcceptHeader = accept_header(Req),
    case mochiweb_util:parse_qvalues(AcceptHeader) of
        invalid_qvalue_string ->
            bad_accept_header;
        QList ->
            [MainType, _SubType] = string:tokens(ContentType, "/"),
            SuperType = MainType ++ "/*",
            lists:any(
                fun({"*/*", Q}) when Q > 0.0 ->
                        true;
                    ({Type, Q}) when Q > 0.0 ->
                        Type =:= ContentType orelse Type =:= SuperType;
                    (_) ->
                        false
                end,
                QList
            ) andalso
            (not lists:member({ContentType, 0.0}, QList)) andalso
            (not lists:member({SuperType, 0.0}, QList))
    end.

%% @doc Filters which of the given media types this request accepts. This filtering
%%      is performed by analyzing the "Accept" header. The returned list is sorted
%%      according to the preferences specified in the "Accept" header (higher Q values
%%      first). If two or more types have the same preference (Q value), they're order
%%      in the returned list is the same as they're order in the input list.
%%
%%      Examples
%%
%%      1) For a missing "Accept" header:
%%         accepted_content_types(["text/html", "application/json"]) ->
%%             ["text/html", "application/json"]
%%
%%      2) For an "Accept" header with value "text/html, application/*":
%%         accepted_content_types(["application/json", "text/html"]) ->
%%             ["application/json", "text/html"]
%%
%%      3) For an "Accept" header with value "text/html, */*; q=0.0":
%%         accepted_content_types(["text/html", "application/json"]) ->
%%             ["text/html"]
%%
%%      4) For an "Accept" header with value "text/html; q=0.5, */*; q=0.1":
%%         accepts_content_types(["application/json", "text/html"]) ->
%%             ["text/html", "application/json"]
%%
-spec(accepted_content_types([string() | binary()], request()) -> [string()] | bad_accept_header).
accepted_content_types(Types1, Req) ->
    Types = lists:map(
        fun(T) -> re:replace(T, "\\s", "", [global, {return, list}]) end,
        Types1),
    AcceptHeader = accept_header(Req),
    case mochiweb_util:parse_qvalues(AcceptHeader) of
        invalid_qvalue_string ->
            bad_accept_header;
        QList ->
            TypesQ = lists:foldr(
                fun(T, Acc) ->
                    case proplists:get_value(T, QList) of
                        undefined ->
                            [MainType, _SubType] = string:tokens(T, "/"),
                            case proplists:get_value(MainType ++ "/*", QList) of
                                undefined ->
                                    case proplists:get_value("*/*", QList) of
                                        Q when is_float(Q), Q > 0.0 ->
                                            [{Q, T} | Acc];
                                        _ ->
                                            Acc
                                    end;
                                Q when Q > 0.0 ->
                                    [{Q, T} | Acc];
                                _ ->
                                    Acc
                            end;
                        Q when Q > 0.0 ->
                            [{Q, T} | Acc];
                        _ ->
                            Acc
                    end
                end,
                [], Types),
            % Note: Stable sort. If 2 types have the same Q value we leave them in the
            % same order as in the input list.
            SortFun = fun({Q1, _}, {Q2, _}) -> Q1 >= Q2 end,
            [Type || {_Q, Type} <- lists:sort(SortFun, TypesQ)]
    end.

accept_header(Req) ->
    case get_header_value("Accept", Req) of
        undefined -> "*/*";
        Value     -> Value
    end.

stop(Reason, #request{transport = Transport, sock = Sock}) ->
    Transport:fast_close(Sock),
    exit(Reason).

