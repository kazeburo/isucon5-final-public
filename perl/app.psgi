use FindBin;
use lib "$FindBin::Bin/local/lib/perl5";
use lib "$FindBin::Bin/lib";
use File::Basename;
use Plack::Builder;
use Isucon5f::Web;
use Cookie::Baker;
use WWW::Form::UrlEncoded::XS qw/parse_urlencoded build_urlencoded/;


my $root_dir = File::Basename::dirname(__FILE__);
my $cookie_name = 'airisu_session';

my $app = Isucon5f::Web->psgi($root_dir);
builder {
    enable 'ReverseProxy';
    enable 'Static',
        path => qr!^/(?:(?:css|fonts|js)/|favicon\.ico$)!,
        root => File::Basename::dirname($root_dir) . '/static';
    enable sub {
        my $mapp = shift;
        sub {
            my $env = shift;
            my $cookie = crush_cookie($env->{HTTP_COOKIE} || '')->{$cookie_name};
            if ( $cookie ) {
               $env->{'psgix.session'} = +{parse_urlencoded($cookie)};
               $env->{'psgix.session.options'} = {
                   id => $cookie
               };
            }
            else {
                $cookie = '{}';
                $env->{'psgix.session'} = {};
                $env->{'psgix.session.options'} = {
                    id => '{}',
                    new_session => 1,
                };
            }

            my $res = $mapp->($env);

            my $cookie2 = build_urlencoded(%{$env->{'psgix.session'}});
            my $bake_cookie;
            if ($env->{'psgix.session.options'}->{expire}) {
                $bake_cookie = bake_cookie( $cookie_name, {
                    value => '{}',
                    path => '/',
                });
            }
            elsif ( $cookie ne $cookie2 ) {
                $bake_cookie = bake_cookie( $cookie_name, {
                    value => $cookie2,
                    path => '/',
                });
            }
            Plack::Util::header_push($res->[1], 'Set-Cookie', $bake_cookie) if $bake_cookie;
            $res;
        };
    };
    $app;
};
