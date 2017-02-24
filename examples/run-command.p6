use SSH::LibSSH;

sub MAIN($host, $user, *@command) {
    my $session = await SSH::LibSSH.connect(:$host, :$user);
    my $channel = await $session.execute(@command.join(' '));
    react {
        whenever $channel.stdout -> $chars {
            $*OUT.print: $chars;
        }
        whenever $channel.stderr -> $chars {
            $*ERR.print: $chars;
        }
    }
    $channel.close;
    $session.close;
}
