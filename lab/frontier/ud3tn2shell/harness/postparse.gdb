set pagination off
set confirm off
set breakpoint pending on
break free_administrative_record
commands
  silent
  if record != 0
    printf "POSTPARSE record=%p type=%d status_report=%p bpdu=%p start=%p\n", record, record->type, record->status_report, record->bpdu, record->start_of_record_ptr
    x/12gx record
  end
  continue
end
run
printf "POSTPARSE_STOP\n"
bt 18
info registers rip rdi rsi
