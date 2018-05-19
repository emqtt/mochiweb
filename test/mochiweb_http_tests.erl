-module(mochiweb_http_tests).

-import(mochiweb_http, [parse_range_request/1, range_skip_length/2]).

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

-ifdef(gen_tcp_r15b_workaround).
-define(SHOULD_HAVE_BUG, true).
-else.
-define(SHOULD_HAVE_BUG, false).
-endif.

start_server() ->
    application:start(inets),
    {ok, Pid} = mochiweb_http:start_link({esockd_transport, nil, nil},
                                          {loop, fun responder/1}),
    Pid.

responder(Req) ->
    mochiweb_request:respond(
      {200, [{"Content-Type", "text/html"}],
       ["<html><body>Hello</body></html>"], Req}).

has_bug(Port, Len) ->
  case
    httpc:request(get, {"http://127.0.0.1:" ++ integer_to_list(Port) ++ "/",
                        [{"X-Random", lists:duplicate(Len, $a)}]}, [], [])
  of
      {error, socket_closed_remotely} ->
          true;
      {ok, {{"HTTP/1.1", 200, "OK"}, _, "<html><body>Hello</body></html>"}} ->
          false;
      {ok, {{"HTTP/1.1", 400, "Bad Request"}, _, []}} ->
          false
  end.

range_test() ->
    %% valid, single ranges
    ?assertEqual([{20, 30}], parse_range_request("bytes=20-30")),
    ?assertEqual([{20, none}], parse_range_request("bytes=20-")),
    ?assertEqual([{none, 20}], parse_range_request("bytes=-20")),

    %% trivial single range
    ?assertEqual([{0, none}], parse_range_request("bytes=0-")),

    %% invalid, single ranges
    ?assertEqual(fail, parse_range_request("")),
    ?assertEqual(fail, parse_range_request("garbage")),
    ?assertEqual(fail, parse_range_request("bytes=-20-30")),

    %% valid, multiple range
    ?assertEqual(
       [{20, 30}, {50, 100}, {110, 200}],
       parse_range_request("bytes=20-30,50-100,110-200")),
    ?assertEqual(
       [{20, none}, {50, 100}, {none, 200}],
       parse_range_request("bytes=20-,50-100,-200")),

    %% valid, multiple range with whitespace
    ?assertEqual(
       [{20, 30}, {50, 100}, {110, 200}],
       parse_range_request("bytes=20-30, 50-100 , 110-200")),

    %% valid, multiple range with extra commas
    ?assertEqual(
       [{20, 30}, {50, 100}, {110, 200}],
       parse_range_request("bytes=20-30,,50-100,110-200")),
    ?assertEqual(
       [{20, 30}, {50, 100}, {110, 200}],
       parse_range_request("bytes=20-30, ,50-100,,,110-200")),

    %% no ranges
    ?assertEqual([], parse_range_request("bytes=")),
    ok.

range_skip_length_test() ->
    Body = <<"012345678901234567890123456789012345678901234567890123456789">>,
    BodySize = byte_size(Body), %% 60
    BodySize = 60,

    %% these values assume BodySize =:= 60
    ?assertEqual({1,9}, range_skip_length({1,9}, BodySize)), %% 1-9
    ?assertEqual({10,10}, range_skip_length({10,19}, BodySize)), %% 10-19
    ?assertEqual({40, 20}, range_skip_length({none, 20}, BodySize)), %% -20
    ?assertEqual({30, 30}, range_skip_length({30, none}, BodySize)), %% 30-

    %% valid edge cases for range_skip_length
    ?assertEqual({BodySize, 0}, range_skip_length({none, 0}, BodySize)),
    ?assertEqual({0, BodySize}, range_skip_length({none, BodySize}, BodySize)),
    ?assertEqual({0, BodySize}, range_skip_length({0, none}, BodySize)),
    BodySizeLess1 = BodySize - 1,
    ?assertEqual({BodySizeLess1, 1},
                 range_skip_length({BodySize - 1, none}, BodySize)),
    ?assertEqual({BodySizeLess1, 1},
                 range_skip_length({BodySize - 1, BodySize+5}, BodySize)),
    ?assertEqual({BodySizeLess1, 1},
                 range_skip_length({BodySize - 1, BodySize}, BodySize)),

    %% out of range, return whole thing
    ?assertEqual({0, BodySize},
                 range_skip_length({none, BodySize + 1}, BodySize)),
    ?assertEqual({0, BodySize},
                 range_skip_length({none, -1}, BodySize)),
    ?assertEqual({0, BodySize},
                 range_skip_length({0, BodySize + 1}, BodySize)),

    %% invalid ranges
    ?assertEqual(invalid_range,
                 range_skip_length({-1, 30}, BodySize)),
    ?assertEqual(invalid_range,
                 range_skip_length({-1, BodySize + 1}, BodySize)),
    ?assertEqual(invalid_range,
                 range_skip_length({BodySize, 40}, BodySize)),
    ?assertEqual(invalid_range,
                 range_skip_length({-1, none}, BodySize)),
    ?assertEqual(invalid_range,
                 range_skip_length({BodySize, none}, BodySize)),
    ok.

-endif.
