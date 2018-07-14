
-module(mochifmt_tests).

-import(mochifmt, [tokenize/1, bformat/2, bformat/3]).

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

-record(conversion, {length, precision, ctype, align, fill_char, sign}).

tokenize_test() ->
    {mochifmt, [{raw, "ABC"}]} = tokenize("ABC"),
    {mochifmt, [{format, {"0", "", ""}}]} = tokenize("{0}"),
    {mochifmt, [{raw, "ABC"}, {format, {"1", "", ""}}, {raw, "DEF"}]} =
        tokenize("ABC{1}DEF"),
    ok.

format_test() ->
    <<"  -4">> = bformat("{0:4}", [-4]),
    <<"   4">> = bformat("{0:4}", [4]),
    <<"   4">> = bformat("{0:{0}}", [4]),
    <<"4   ">> = bformat("{0:4}", ["4"]),
    <<"4   ">> = bformat("{0:{0}}", ["4"]),
    <<"1.2yoDEF">> = bformat("{2}{0}{1}{3}", {yo, "DE", 1.2, <<"F">>}),
    <<"cafebabe">> = bformat("{0:x}", {16#cafebabe}),
    <<"CAFEBABE">> = bformat("{0:X}", {16#cafebabe}),
    <<"CAFEBABE">> = bformat("{0:X}", {16#cafebabe}),
    <<"755">> = bformat("{0:o}", {8#755}),
    <<"a">> = bformat("{0:c}", {97}),
    %% Horizontal ellipsis
    <<226, 128, 166>> = bformat("{0:c}", {16#2026}),
    <<"11">> = bformat("{0:b}", {3}),
    <<"11">> = bformat("{0:b}", [3]),
    <<"11">> = bformat("{three:b}", [{three, 3}]),
    <<"11">> = bformat("{three:b}", [{"three", 3}]),
    <<"11">> = bformat("{three:b}", [{<<"three">>, 3}]),
    <<"\"foo\"">> = bformat("{0!r}", {"foo"}),
    <<"2008-5-4">> = bformat("{0.0}-{0.1}-{0.2}", {{2008,5,4}}),
    <<"2008-05-04">> = bformat("{0.0:04}-{0.1:02}-{0.2:02}", {{2008,5,4}}),
    <<"foo6bar-6">> = bformat("foo{1}{0}-{1}", {bar, 6}),
    <<"-'atom test'-">> = bformat("-{arg!r}-", [{arg, 'atom test'}]),
    <<"2008-05-04">> = bformat("{0.0:0{1.0}}-{0.1:0{1.1}}-{0.2:0{1.2}}",
                               {{2008,5,4}, {4, 2, 2}}),
    ok.

std_test() ->
    M = mochifmt_std:new(),
    <<"01">> = bformat("{0}{1}", [0, 1], M),
    ok.

records_test() ->
    M = mochifmt_records:new([{conversion, record_info(fields, conversion)}]),
    R = #conversion{length=long, precision=hard, sign=peace},
    long = mochifmt_records:get_value("length", R, M),
    hard = mochifmt_records:get_value("precision", R, M),
    peace = mochifmt_records:get_value("sign", R, M),
    <<"long hard">> = bformat("{length} {precision}", R, M),
    <<"long hard">> = bformat("{0.length} {0.precision}", [R], M),
    ok.

-endif.

