use SSH::LibSSH;

sub MAIN($host, $user, *@command) {
    my $session = await SSH::LibSSH.connect(:$host, :$user);
    my $channel = await $session.execute(@command.join(' '));
    my $exit-code;
    react {
        whenever $channel.stdout -> $chars {
            $*OUT.print: $chars;
        }
        whenever $channel.stderr -> $chars {
            $*ERR.print: $chars;
        }
        whenever $channel.exit -> $code {
            $exit-code = $code;
        }
    }
    $channel.close;
    $session.close;
    exit $exit-code;
}
