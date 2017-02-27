use SSH::LibSSH::Raw;
use NativeCall :types;

class X::SSH::LibSSH::Error {
    has Str $.message;
}

class SSH::LibSSH {
    multi sub error-check($what, $result) {
        if $result == -1 {
            die X::SSH::LibSSH::Error.new(message => "Failed to $what");
        }
        $result
    }
    multi sub error-check(SSHSession $s, $result) {
        if $result == -1 {
            die X::SSH::LibSSH::Error.new(message => ssh_get_error($s));
        }
        $result
    }

    # We use libssh exclusively in non-blocking mode. A single event loop
    # thread manages all interactions with libssh (that is, we only ever make
    # calls to the native API on the one thread spawned by the EventLoop
    # class). Operations are shipped to the event loop via. a channel, and
    # Promise/Supply are used for conveying results. This is the simplest
    # possible non-terrible event loop: it uses dopoll so it isn't in a busy
    # loop, but then it checks for completion of all outstanding operations.
    # This will be fine for a handful of connections, but will scale pretty
    # badly if there are dozens/hundreds. For some (the channel) events there
    # is a callback-based API, which would greatly reduce the number of things
    # we need to poll. However, it needs filling a struct up with callbacks to
    # use it; NativeCall couldn't do that at the time of writing, and the
    # use-case that prompted writing this module only required that it handle
    # a few concurrent connections. So, this approach was fine enough.
    my class EventLoop {
        has Channel $!todo;
        has Thread $!loop-thread;
        has SSHEvent $!loop;
        has int $!active-sessions;
        has @!pollers;

        submethod BUILD() {
            $!todo = Channel.new;
            $!loop-thread = Thread.start: :app_lifetime, {
                $!loop = ssh_event_new();
                loop {
                    if $!active-sessions {
                        # We have active sessions, so we'll look for any new
                        # work, then poll the libssh event loop and run any
                        # active poll check callbacks.
                        while $!todo.poll -> &task {
                            task();
                        }
                        ssh_event_dopoll($!loop, 20);
                        @!pollers .= grep: -> &p {
                            my $remove = False;
                            p($remove);
                            !$remove
                        }
                    }
                    else {
                        my &task = $!todo.receive;
                        task();
                    }
                }
            }
        }

        method run-on-loop(&task --> Nil) {
            $!todo.send(&task);
        }

        method add-session(SSHSession $session --> Nil) {
            self!assert-loop-thread();
            error-check('add session to event loop',
                ssh_event_add_session($!loop, $session));
            $!active-sessions++;
        }

        method remove-session(SSHSession $session --> Nil) {
            self!assert-loop-thread();
            error-check('remove session from event loop',
                ssh_event_remove_session($!loop, $session));
            $!active-sessions--;
        }

        method add-poller(&poller --> Nil) {
            self!assert-loop-thread();
            @!pollers.push: &poller;
        }

        method !assert-loop-thread() {
            die "Can only call this method on the SSH event loop thread"
                unless $*THREAD === $!loop-thread;
        }
    }

    # The event loop involves creating a thread and a little setup work, so
    # we won't do it until we actually need it, to be cheaper in apps that may
    # use the module but never actually make an SSH connection.
    my Lock $setup-event-loop-lock .= new;
    my EventLoop $event-loop;
    sub get-event-loop() {
        $event-loop // $setup-event-loop-lock.protect: {
            $event-loop //= EventLoop.new;
        }
    }

    class Channel { ... }
    class Session {
        my enum State <Fresh Connected Disconnected>;
        has $!state = Fresh;
        has Str $.host;
        has Int $.port;
        has Str $.user;
        has SSHSession $.session-handle;

        submethod BUILD(Str :$!host!, Int :$!port = 22, Str :$!user = $*USER.Str) {
        }

        method connect(:$scheduler = $*SCHEDULER --> Promise) {
            my $p = Promise.new;
            my $v = $p.vow;
            given get-event-loop() -> $loop {
                $loop.run-on-loop: {
                    with $!session-handle = ssh_new() -> $s {
                        ssh_set_blocking($s, 0);
                        error-check($s,
                            ssh_options_set_str($s, SSH_OPTIONS_HOST, $!host));
                        error-check($s,
                            ssh_options_set_int($s, SSH_OPTIONS_PORT, CArray[int32].new($!port)));
                        error-check($s,
                            ssh_options_set_str($s, SSH_OPTIONS_USER, $!user));

                        my $outcome = error-check($s, ssh_connect($s));
                        $loop.add-session($s);
                        if $outcome == 0 {
                            # Connected "immediately", more on to auth server.
                            self!connect-auth-server($v, $scheduler);
                        }
                        else {
                            # Will need to poll.
                            $loop.add-poller: -> $remove is rw {
                                if error-check($s, ssh_connect($s)) == 0 {
                                    $remove = True;
                                    self!connect-auth-server($v, $scheduler);
                                }
                                CATCH {
                                    default {
                                        $remove = True;
                                        $v.break($_);
                                    }
                                }
                            }
                        }
                    }
                    else {
                        die X::LibSSH::SSH.new(message => 'Could not allocate SSH session');
                    }
                    CATCH {
                        default {
                            $v.break($_);
                        }
                    }
                }
            }
            $p
        }

        # Performs the server authorization step of connecting.
        method !connect-auth-server($v, $scheduler) {
            given $!session-handle -> $s {
                my $known = SSHServerKnown(error-check($s, ssh_is_server_known($s)));
                if $known == SSH_SERVER_KNOWN_OK {
                    self!connect-auth-user($v, $scheduler);
                }
                else {
                    # TODO Implement something pluggable/extensible here.
                    $v.break(X::NYI.new(feature => 'Handling unknown servers'));
                }
            }
        }

        # Performs the user authorization step of connecting.
        method !connect-auth-user($v, $scheduler) {
            given $!session-handle -> $s {
                my $auth-outcome = SSHAuth(error-check($s,
                    ssh_userauth_publickey_auto($s, Str, Str)));
                if $auth-outcome != SSH_AUTH_AGAIN {
                    self!process-auth-outcome($auth-outcome, $v);
                }
                else {
                    # Poll until result available.
                    get-event-loop().add-poller: -> $remove is rw {
                        my $auth-outcome = SSHAuth(error-check($s,
                            ssh_userauth_publickey_auto($s, Str, Str)));
                        if $auth-outcome != SSH_AUTH_AGAIN {
                            $remove = True;
                            self!process-auth-outcome($auth-outcome, $v);
                        }
                        CATCH {
                            default {
                                $remove = True;
                                $v.break($_);
                            }
                        }
                    }
                }
                CATCH {
                    default {
                        $v.break($_);
                    }
                }
            }
        }

        method !process-auth-outcome($outcome, $v) {
            if $outcome == SSH_AUTH_SUCCESS {
                $v.keep(self);
            }
            else {
                $v.break(X::SSH::LibSSH::Error.new(message => 'Authentication failed'));
            }
        }

        method execute($command --> Promise) {
            my $p = Promise.new;
            my $v = $p.vow;
            given get-event-loop() -> $loop {
                $loop.run-on-loop: {
                    my $channel = ssh_channel_new($!session-handle);
                    with $channel {
                        my $open = error-check($!session-handle,
                            ssh_channel_open_session($channel));
                        if $open == 0 {
                            self!execute-on-channel($channel, $command, $v);
                        }
                        else {
                            $loop.add-poller: -> $remove is rw {
                                my $open = error-check($!session-handle,
                                    ssh_channel_open_session($channel));
                                if $open == 0 {
                                    $remove = True;
                                    self!execute-on-channel($channel, $command, $v);
                                }
                                CATCH {
                                    default {
                                        $remove = True;
                                        $v.break($_);
                                    }
                                }
                            }
                        }
                        CATCH {
                            default {
                                $v.break($_);
                            }
                        }
                    }
                    else {
                        $v.break(X::SSH::LibSSH::Error.new(message => 'Could not allocate channel'));
                    }
                }
            }
            $p
        }

        method !execute-on-channel(SSHChannel $channel, Str $command, $v) {
            my $exec = error-check($!session-handle,
                ssh_channel_request_exec($channel, $command));
            if $exec == 0 {
                $v.keep(Channel.from-raw-handle($channel, self));
            }
            else {
                get-event-loop().add-poller: -> $remove is rw {
                    my $exec = error-check($!session-handle,
                        ssh_channel_request_exec($channel, $command));
                    if $exec == 0 {
                        $remove = True;
                        $v.keep(Channel.from-raw-handle($channel, self));
                    }
                    CATCH {
                        default {
                            $remove = True;
                            $v.break($_);
                        }
                    }
                }
            }
            CATCH {
                default {
                    $v.break($_);
                }
            }
        }

        method close() {
            my $p = Promise.new;
            given get-event-loop() -> $loop {
                $loop.run-on-loop: {
                    with $!session-handle {
                        ssh_disconnect($_);
                        ssh_free($_);
                    }
                    $!session-handle = SSHSession;
                    $p.keep(True);
                    CATCH {
                        default {
                            $p.break($_);
                        }
                    }
                }
            }
            await $p;
        }
    }

    class Channel {
        has Session $.session;
        has SSHChannel $.channel-handle;

        method new() {
            die X::SSH::LibSSH::Error.new(message =>
                'A channel cannot be created directly. Use a method on Session to make one.');
        }

        method from-raw-handle($channel-handle, $session) {
            self.bless(:$channel-handle, :$session)
        }

        submethod BUILD(SSHChannel :$!channel-handle!, Session :$!session) {}

        method stdout(*%options --> Supply) {
            self!std-reader(0, |%options)
        }

        method stderr(*%options --> Supply) {
            self!std-reader(1, |%options)
        }

        method !std-reader($is-stderr, :$scheduler = $*SCHEDULER) {
            my Supplier::Preserving $s .= new;
            given get-event-loop() -> $loop {
                $loop.run-on-loop: {
                    $loop.add-poller: -> $remove is rw {
                        my $buf = Buf.allocate(32768);
                        my $nread = error-check($!session.session-handle,
                            ssh_channel_read_nonblocking($!channel-handle, $buf, 32768, $is-stderr));
                        if $nread > 0 {
                            $buf .= subbuf(0, $nread);
                            $s.emit($buf.decode('ascii')); # XXX bin/enc
                        }
                        elsif ssh_channel_is_eof($!channel-handle) {
                            $remove = True;
                            $s.done();
                        }
                        CATCH {
                            default {
                                $remove = True;
                                $s.quit($_);
                            }
                        }
                    }
                }
            }
            $s.Supply # XXX use .schedule-on or so, but check we don't lose sequence
        }

        method write(Blob:D $data --> Promise) {
            my $p = Promise.new;
            my $v = $p.vow;
            given get-event-loop() -> $loop {
                my $remaining = $data;
                sub maybe-send-something-now() {
                    my uint $ws = ssh_channel_window_size($!channel-handle);
                    my $send = [min] $ws, 0xFFFF, $remaining.elems;
                    if $send {
                        my $rv = error-check($!session.session-handle,
                            ssh_channel_write($!channel-handle, $remaining, $send));
                        $remaining = $remaining.subbuf($send);
                        CATCH {
                            default {
                                $v.break($_);
                                return True;
                            }
                        }
                        if $remaining.elems == 0 {
                            $v.keep(True);
                            return True;
                        }
                    }
                    return False;
                }

                unless maybe-send-something-now() {
                    $loop.add-poller: -> $remove is rw {
                        $remove = maybe-send-something-now();
                    }
                }
            }
            $p
        }

        method close-stdin() {
            my $p = Promise.new;
            my $v = $p.vow;
            given get-event-loop() -> $loop {
                error-check($!session.session-handle, ssh_channel_send_eof($!channel-handle));
                $v.keep(True);
                CATCH {
                    default {
                        $v.break($_);
                    }
                }
            }
            await $p;
        }

        method exit() {
            my $p = Promise.new;
            my $v = $p.vow;
            given get-event-loop() -> $loop {
                $loop.run-on-loop: {
                    $loop.add-poller: -> $remove is rw {
                        my $exit = ssh_channel_get_exit_status($!channel-handle);
                        if $exit >= 0 {
                            $remove = True;
                            $v.keep($exit);
                        }
                    }
                }
            }
            $p
        }

        method close() {
            my $p = Promise.new;
            my $v = $p.vow;
            get-event-loop().run-on-loop: {
                with $!channel-handle {
                    error-check('close a channel', ssh_channel_close($_));
                    ssh_channel_free($_);
                }
                $!channel-handle = SSHChannel;
                $v.keep(True);
                CATCH {
                    default {
                        $v.break($_);
                    }
                }
            }
            await $p;
        }
    }

    method connect(Str :$host!, *%options --> Promise) {
        Session.new(:$host, |%options).connect
    }
}
