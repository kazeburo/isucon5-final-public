package Isucon5f::Web;

use 5.020;
use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use JSON;
use Furl;
use URI;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use String::Util qw(trim);
use File::Basename qw(dirname);
use File::Spec;
use Cache::Memcached::Fast;
use Sereal;
use Digest::SHA qw/sha512 sha1_hex/;
use Time::HiRes;

my $isu02a_ip = '203.104.208.174';
my $isu02b_ip = '203.104.208.175';
my $isu02c_ip = '203.104.208.176';

sub db {
    state $db ||= do {
        my %db = (
            host => $ENV{ISUCON5_DB_HOST} || $isu02a_ip,
            port => $ENV{ISUCON5_DB_PORT} || 5432,
            username => $ENV{ISUCON5_DB_USER} || 'isucon',
            password => $ENV{ISUCON5_DB_PASSWORD},
            database => $ENV{ISUCON5_DB_NAME} || 'isucon5f',
        );
        DBIx::Sunny->connect(
            "dbi:Pg:dbname=$db{database};host=$db{host};port=$db{port}", $db{username}, $db{password}, {
                RaiseError => 1,
                PrintError => 0,
                AutoInactiveDestroy => 1,
            },
        );
    };
}

my $s_decoder = Sereal::Decoder->new();
my $s_encoder = Sereal::Encoder->new();
my $memcached;
sub memcached {
    $memcached ||= Cache::Memcached::Fast->new({
        servers => [
            { address => "$isu02b_ip:11211",noreply=>1},
            { address => "$isu02c_ip:11211",noreply=>1}
        ],
        serialize_methods => [ sub { $s_encoder->encode($_[0])},
                               sub { $s_decoder->decode($_[0])} ],
    }),
}

my %c_endpoints = (
    ken => {service => 'ken',                 meth => 'GET', token_type => undef,    token_key => undef,                      uri => 'http://api.five-final.isucon.net:8080/%s'},
    ken2 => {service => 'ken2',                meth => 'GET', token_type => undef,    token_key => undef,                      uri => 'http://api.five-final.isucon.net:8080/' },
    surname => {service => 'surname',             meth => 'GET', token_type => undef,    token_key => undef,                      uri => 'http://api.five-final.isucon.net:8081/surname' },
    givenname => {service => 'givenname',           meth => 'GET', token_type => undef,    token_key => undef,                      uri => 'http://api.five-final.isucon.net:8081/givenname' },
    tenki => {service => 'tenki',               meth => 'GET', token_type => 'param',  token_key => 'zipcode',                  uri => 'http://api.five-final.isucon.net:8988/' },
    perfectsec => {service => 'perfectsec',          meth => 'GET', token_type => 'header', token_key => 'X-PERFECT-SECURITY-TOKEN', uri => 'https://api.five-final.isucon.net:8443/tokens' },
    perfectsec_attacked => {service => 'perfectsec_attacked', meth => 'GET', token_type => 'header', token_key => 'X-PERFECT-SECURITY-TOKEN', uri => 'https://api.five-final.isucon.net:8443/attacked_list' },
);

if(0) {
    $c_endpoints{ken}{uri}       = 'http://127.0.0.1:9001/%s';
    $c_endpoints{ken2}{uri}      = 'http://127.0.0.1:9002/';
    $c_endpoints{surname}{uri}   = 'http://127.0.0.1:9003/surname';
    $c_endpoints{givenname}{uri} = 'http://127.0.0.1:9004/givenname';
    $c_endpoints{tenki}{uri}     = 'http://127.0.0.1:9005/';
}


sub load_users_to_memcached {
    my $db = do {
        my %db = (
            host => $ENV{ISUCON5_DB_HOST} || $isu02a_ip,
            port => $ENV{ISUCON5_DB_PORT} || 5432,
            username => $ENV{ISUCON5_DB_USER} || 'isucon',
            password => $ENV{ISUCON5_DB_PASSWORD},
            database => $ENV{ISUCON5_DB_NAME} || 'isucon5f',
        );
        DBIx::Sunny->connect(
            "dbi:Pg:dbname=$db{database};host=$db{host};port=$db{port}", $db{username}, $db{password}, {
                RaiseError => 1,
                PrintError => 0,
                AutoInactiveDestroy => 1,
            },
        );
    };
    for my $user (@{$db->select_all('SELECT * FROM users')}) {
        memcached()->set("user:$user->{id}", $user);
        memcached()->set("user_email:$user->{email}", $user);
    }
}
sub load_subscriptions_to_memcached {
    my $db = do {
        my %db = (
            host => $ENV{ISUCON5_DB_HOST} || $isu02a_ip,
            port => $ENV{ISUCON5_DB_PORT} || 5432,
            username => $ENV{ISUCON5_DB_USER} || 'isucon',
            password => $ENV{ISUCON5_DB_PASSWORD},
            database => $ENV{ISUCON5_DB_NAME} || 'isucon5f',
        );
        DBIx::Sunny->connect(
            "dbi:Pg:dbname=$db{database};host=$db{host};port=$db{port}", $db{username}, $db{password}, {
                RaiseError => 1,
                PrintError => 0,
                AutoInactiveDestroy => 1,
            },
        );
    };
    for my $subscription (@{$db->select_all('SELECT * FROM subscriptions')}) {
        memcached()->set("subscription:$subscription->{user_id}", $subscription);
    }
}

my ($SELF, $C);
sub session : lvalue {
    $C->req->env->{"psgix.session"};
}

sub stash {
    $C->stash;
}

sub authenticate {
    my ($email, $password) = @_;
    my $user = memcached()->get("user_email:" . $email);
    if ( $user && sha512($user->{salt} . $password) eq $user->{passhash} ) {
        session->{user_id} = $user->{id};
        stash->{user} = $user;
    }
    return $user;
}

sub current_user {
    my $user = stash->{user};
    return $user if $user;
    return undef if !session->{user_id};

    $user = memcached()->get("user:" . session->{user_id});
    if (!$user) {
        session = +{};
    } else {
        stash->{user} = $user;
    }
    return $user;
}

my @SALT_CHARS = ('a'..'z', 'A'..'Z', '0'..'9');
sub generate_salt {
    my $salt = '';
    $salt .= $SALT_CHARS[int(rand(0+@SALT_CHARS))] for 1..32;
    $salt;
}

filter 'set_global' => sub {
    my ($app) = @_;
    sub {
        my ($self, $c) = @_;
        $SELF = $self;
        $C = $c;
        $app->($self, $c);
    }
};

get '/signup' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session = +{};
    $c->render('signup.tx');
};

post '/signup' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $params = $c->req->parameters;
    my $email = $params->{email};
    my $password = $params->{password};
    my $grade = $params->{grade};
    my $salt = generate_salt();
    my $insert_user_query = <<SQL;
INSERT INTO users (email,salt,passhash,grade) VALUES (?,?,digest(? || ?, 'sha512'),?) RETURNING id
SQL
    my $default_arg = +{};
    my $insert_subscription_query = <<SQL;
INSERT INTO subscriptions (user_id,arg) VALUES (?,?)
SQL
    {
        my $txn = db->txn_scope;
        my $user_id = db->select_one($insert_user_query, $email, $salt, $salt, $password, $grade);
        db->query($insert_subscription_query, $user_id, to_json($default_arg));
        $txn->commit;
        my $user = db()->select_row('SELECT * FROM users WHERE id = ?', $user_id);
        memcached()->set("user:$user_id", $user);
        memcached()->set("user_email:$user->{email}", $user);
        memcached()->set("subscription:$user_id", db()->select_row('SELECT * FROM subscriptions WHERE user_id = ?', $user_id));
    }


    $c->redirect('/login');
};

post '/cancel' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    $c->redirect('/signup');
};

get '/login' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session = +{};
    $c->render('login.tx');
};

post '/login' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $email = $c->req->param("email");
    my $password = $c->req->param("password");
    authenticate($email, $password);
    $c->halt(403) if !current_user();
    $c->redirect('/');
};

get '/logout' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session = +{};
    $c->redirect('/login');
};

get '/' => [qw(set_global)] => sub {
    my ($self, $c) = @_;

    if (!current_user()) {
        return $c->redirect('/login');
    }
    $c->render('main.tx', { user => current_user() });
};

get '/user.js' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    $c->halt(403) if !current_user();
    $c->res->header('Content-Type', 'application/javascript');

    my $grade_to_interval = {
        micro => 'var AIR_ISU_REFRESH_INTERVAL = 30000;',
        small => 'var AIR_ISU_REFRESH_INTERVAL = 30000;',
        standard => 'var AIR_ISU_REFRESH_INTERVAL = 20000;',
        premium => 'var AIR_ISU_REFRESH_INTERVAL = 10000;',
    };

#    $c->render('userjs.tx', { grade => current_user()->{grade} });
    $c->res->body($grade_to_interval->{current_user()->{grade} });
};

get '/modify' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $user = current_user();
    $c->halt(403) if !$user;

    my $arg = memcached()->get("subscription:" . $user->{id});
    $c->render('modify.tx', { user => $user, arg => $arg });
};

post '/modify' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $user = current_user();
    $c->halt(403) if !$user;
    my $params = $c->req->parameters;
    my $service = $params->{service} ? trim($params->{service}): undef;
    my $token = $params->{token} ? trim($params->{token}) : undef;
    my $keys = $params->{keys} ? [split(/\s+/, trim($params->{keys}))] : undef;
    my $param_name = $params->{param_name} ? trim($params->{param_name}) : undef;
    my $param_value = $params->{param_value} ? trim($params->{param_value}) : undef;
    my $select_query = <<SQL;
SELECT arg FROM subscriptions WHERE user_id=? FOR UPDATE
SQL
    my $update_query = <<SQL;
UPDATE subscriptions SET arg=? WHERE user_id=?
SQL
    {
        my $txn = db->txn_scope;
        my $arg_json = db->select_one($select_query, $user->{id});
        my $arg = from_json($arg_json);
        if (!$arg->{$service}) { $arg->{$service} = +{}; }
        if ($token) { $arg->{$service}{token} = $token; }
        if ($keys) { $arg->{$service}{keys} = $keys; }
        if ($param_name && $param_value) {
            if (!$arg->{$service}{params}) { $arg->{$service}{params} = +{}; }
            $arg->{$service}{params}{$param_name} = $param_value;
        }
        db->query($update_query, to_json($arg), $user->{id});
        $txn->commit;
    }
    my $subscription = db()->select_row('SELECT * FROM subscriptions WHERE user_id = ?', $user->{id});
    memcached()->set("subscription:$user->{id}", $subscription);
    load_subscription_and_cache($subscription);

    $c->redirect('/modify');
};

sub load_subscription_and_cache {
    my $subscription = shift;
    my $arg_json = $subscription->{arg};
    my $arg = from_json($arg_json);

    my $data = [];

    while (my ($service, $conf) = each(%$arg)) {
        my $row = $c_endpoints{$service};
        my $method = $row->{meth};
        my $token_type = $row->{token_type};
        my $token_key = $row->{token_key};
        my $uri_template = $row->{uri};
        my $headers = +{};
        my $params = $conf->{params} || +{};
        given ($token_type) {
            when ('header') {
                $headers->{$token_key} = $conf->{'token'};
            }
            when ('param') {
                $params->{$token_key} = $conf->{'token'};
            }
        }
        my $uri = sprintf($uri_template, @{$conf->{keys} || []});
        fetch_api($service, $method, $uri, $headers, $params);
    }
}

sub generate_key {
    my ($service, $method, $uri, $headers, $params) = @_;

    #my $time_key = '';
    #if($service eq 'tenki') {
    #    # 0.5秒単位のキャッシュを作る
    #
    #    my ($epocsec, $microsec) = Time::HiRes::gettimeofday();
    #    my $msec = $microsec / 1000;
    #    # 000..499 => 000;
    #    # 500..999 => 500;
    #    my $msec_key = $msec < 500 ? 0 : 500;
    #    $time_key = sprintf("%d.%3d\n", $epocsec, $msec_key);
    #}
    return sha1_hex('api:' . $service . ':' . encode_json([ $method, $uri, $headers, $params ]));
}

my %expire_map = (
    'tenki' => 3,
);
sub fetch_api {
    my ($service, $method, $uri, $headers, $params) = @_;

    my $key = generate_key(@_);
    my $data = memcached->get($key);
    return $data if($data);

    $data = fetch_api_raw(@_);
    my $expire = $expire_map{$service} || 30; # @@@ とりあえず 30秒
    memcached->set($key, $data, $expire);
    return $data;
}

sub fetch_api_raw {
    my ($service, $method, $uri, $headers, $params) = @_;
    my $client = stash->{client};
    $client ||= Furl::HTTP->new(
        ssl_opts => { SSL_verify_mode => SSL_VERIFY_NONE },
        #connection_pool => Plack::Util::inline_object(
        #    steal => sub{ my $key = $_[0].':'.$_[1]; stash->{$key} },
        #    push => sub{ my $key = $_[0].':'.$_[1]; stash->{$key} = $_[2]  }
        #),
    );
    stash->{client} = $client;
    $uri = URI->new($uri);
    $uri->query_form(%$params);
    my ($minor_version, $code, $msg, $res_headers, $body) = $client->request(
        method     => $method,
        host       => $uri->host,
        port       => $uri->port,
        path_query => $uri->path_query,
        scheme     => $uri->scheme,
        headers => [%$headers],
    );

    # if($service eq 'tenki') {
    #     warn(encode_json({
    #             fetch_api_result => {
    #                         uri => $uri->as_string,
    #                                 method => $method,
    #                                 headers => $headers,
    #                                 params => $params,
    #                                 result => $body,
    #                             }
    #                 }));
    # }
    return decode_json($body);
}

get '/data' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $user = current_user();
    $c->halt(403) if !$user;

    my $subscription = memcached()->get("subscription:" . $user->{id});
    my $arg_json = $subscription->{arg};
    my $arg = from_json($arg_json);

    my $data = [];

    my @key_list;
    my %key_to_param;
    while (my ($service, $conf) = each(%$arg)) {
        my $row = $c_endpoints{$service};
        my $method = $row->{meth};
        my $token_type = $row->{token_type};
        my $token_key = $row->{token_key};
        my $uri_template = $row->{uri};
        my $headers = +{};
        my $params = $conf->{params} || +{};
        given ($token_type) {
            when ('header') {
                $headers->{$token_key} = $conf->{'token'};
            }
            when ('param') {
                $params->{$token_key} = $conf->{'token'};
            }
        }
        my $uri = sprintf($uri_template, @{$conf->{keys} || []});
        my $key = generate_key($service, $method, $uri, $headers, $params);
        push(@key_list, $key);
        $key_to_param{$key} = [ $service, $method, $uri, $headers, $params ];
    }
    my $result = memcached()->get_multi(@key_list);
    foreach my $key ( @key_list) {
        my $value = $result->{$key};
        my ($service, $method, $uri, $headers, $params) = @{$key_to_param{$key}};
        if( !$value ) {
            $value = fetch_api_raw($service, $method, $uri, $headers, $params);
            my $expire = $expire_map{$service} || 30; # @@@ とりあえず 30秒
            memcached->set($key, $value, $expire);
        }
        push @$data, { service => $service, data => $value };
    }

    $c->res->header('Content-Type', 'application/json');
    $c->res->body(encode_json($data));
};

get '/initialize' => sub {
    my ($self, $c) = @_;
    my $file = File::Spec->rel2abs("../../sql/initialize.sql", dirname(dirname(__FILE__)));
    system("psql", "-f", $file, "isucon5f");
#    memcached->flush_all();
    load_users_to_memcached();
    load_subscriptions_to_memcached();
    [200];
};


1;
