%% Hold a real actor mailbox while a controlled clock crosses the deadline.
-module(warden_store_barrier_ffi).
-export([suspend/1, resume/1, queue_length/1]).

suspend(Pid) -> sys:suspend(Pid), nil.
resume(Pid) -> sys:resume(Pid), nil.
queue_length(Pid) ->
    {message_queue_len, Count} = process_info(Pid, message_queue_len),
    Count.
