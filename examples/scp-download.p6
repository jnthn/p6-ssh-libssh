use SSH::LibSSH;

sub MAIN($host, $user) {
    my $session = await SSH::LibSSH.connect(:$host, :$user);
    await $session.scp-download('/home/jnthn/foobar', 'foobar');
    $session.close;
}
