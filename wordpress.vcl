acl purge {
    "localhost";
    "127.0.0.1";
}

sub vcl_backend_response {
  if ( (!(bereq.url ~ "(wp-(login|admin)|login)")) || (bereq.method == "GET") ) {
    unset beresp.http.set-cookie;
    set beresp.ttl = 1h;
  }

  if (bereq.url ~ "\.(gif|jpg|jpeg|swf|css|js|flv|mp3|mp4|pdf|ico|png)(\?.*|)$") {
    set beresp.ttl = 365d;
  }
}

sub vcl_recv {
  if (req.method == "PURGE") {
    if (!client.ip ~ purge) {
      return (synth(405, "Not allowed."));
    }
    return (hash);
  }

  if (req.url ~ "\.(gif|jpg|jpeg|swf|css|js|flv|mp3|mp4|pdf|ico|png)(\?.*|)$") {
    unset req.http.cookie;
    set req.url = regsub(req.url, "\?.*$", "");
  }

  if (req.url ~ "\?(utm_(campaign|medium|source|term)|adParams|client|cx|eid|fbid|feed|ref(id|src)?|v(er|iew))=") {
    set req.url = regsub(req.url, "\?.*$", "");
  }

  if (req.url ~ "wp-(login|admin)" || req.url ~ "preview=true" || req.url ~ "xmlrpc.php") {
    return (pass);
  }

  if (req.http.cookie) {
    if (req.http.cookie ~ "(wordpress_|wp-settings-)") {
      return(pass);
    } else {
      unset req.http.cookie;
    }
  }
}

# Needed for SSL support
sub vcl_hash {
   if ( req.http.X-Forwarded-Proto ) {
    hash_data( req.http.X-Forwarded-Proto );
   }
}

sub vcl_deliver {
# multi-server webfarm? set a variable here so you can check
# the headers to see which frontend served the request
#   set resp.http.X-Server = "server-01";
   if (obj.hits > 0) {
     set resp.http.X-Cache = "HIT";
   } else {
     set resp.http.X-Cache = "MISS";
   }
}
sub vcl_hit {
  if (req.method == "PURGE") {
    return (synth(200, "OK"));
  }
}

sub vcl_miss {
  if (req.method == "PURGE") {
    return (synth(404, "Not cached"));
  }
}
