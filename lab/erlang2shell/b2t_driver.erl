%% CVE-2026-55737 / GHSA-446w-268v-9462 real-VM driver.
%% Run with the pinned vulnerable OTP ASan emulator; no network, no listener.
%% Each case is a verbatim external-term-format byte string.
-module(b2t_driver).
-export([run/0]).

run() ->
    %% Advisory arity 0x80000000; small body. decoded_size CHKSIZE must reject.
    case_report("small_80000000", <<131,105,128,0,0,0,97,42>>),
    %% Same mismatch with the other high-bit arity used by the direct harness.
    case_report("small_fffffffe", <<131,105,255,255,255,254,97,42>>),
    %% Forged compressed envelope: declared inflated length 0x80000000, but the
    %% body actually inflates to a tiny term. binary2term_prepare must reject.
    Safe = <<131,105,0,0,0,3,97,1,97,2,97,3>>,
    case_report("forged_compressed", <<131,80,128,0,0,0,(zlib:compress(Safe))/binary>>),
    %% Positive small arity: the safe control, must decode to {1,2,3}.
    case_report("safe_positive_3", Safe),
    ok.

case_report(Name, Bin) ->
    try binary_to_term(Bin) of
        Term -> io:format("~s RC=ok TERM=~p~n", [Name, Term])
    catch
        error:badarg -> io:format("~s RC=badarg~n", [Name]);
        Class:Reason -> io:format("~s RC=~p:~p~n", [Name, Class, Reason])
    end.
