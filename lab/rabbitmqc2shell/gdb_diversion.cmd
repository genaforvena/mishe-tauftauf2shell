set pagination off
set confirm off
break amqp_socket_send
run
printf "AT amqp_socket_send after the library copy:\n"
printf "self=%p klass=%p\n", self, self->klass
x/4gx self
printf "continuing into the vtable call\n"
continue
printf "STOPPED AFTER CONTINUE\n"
bt 6
info registers rip
quit
