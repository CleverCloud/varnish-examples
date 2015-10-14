# Only allow purging from specific IPs
acl purge {
    "localhost";
    "127.0.0.1";
}

# This function is used when a request is send by a HTTP client (Browser)
sub vcl_recv {
  # Normalize the header, remove the port (in case you're testing this on various TCP ports)
  set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
  # Remove has_js and CloudFlare/Google Analytics __* cookies.
  set req.http.Cookie = regsuball(req.http.Cookie, "(^|;\s*)(_[_a-z]+|has_js)=[^;]*", "");
  # Remove a ";" prefix, if present.
  set req.http.Cookie = regsub(req.http.Cookie, "^;\s*", "");
  # Allow purging from ACL
  if (req.method == "PURGE") {
    # If not allowed then a error 405 is returned
    if (!client.ip ~ purge) {
      return(synth(405, "This IP is not allowed to send PURGE requests."));
    }
    # If allowed, do a cache_lookup -> vlc_hit() or vlc_miss()
    return (purge);
  }
  # Post requests will not be cached
  if (req.http.Authorization || req.method == "POST") {
    return (pass);
  }
  if (req.method == "GET" && (req.url ~ "^/?mylogout=")) {
      unset req.http.Cookie;
      return (pass);
  }
  #we should not cache any page for Prestashop backend
  if (req.method == "GET" && (req.url ~ "^/admin70")) {
      return (pass);
  }
  #we should not cache any page for customers
  if (req.method == "GET" && (req.url ~ "^/authentification" || req.url ~ "^/my-account")) {
      return (pass);
  }
  #we should not cache any page for customers
  if (req.method == "GET" && (req.url ~ "^/identity" || req.url ~ "^/my-account.php")) {
      return (pass);
  }
  #we should not cache any page for sales
  if (req.method == "GET" && (req.url ~ "^/cart.php" || req.url ~ "^/order.php")) {
      return (pass);
  }
  #we should not cache any page for sales
  if (req.method == "GET" && (req.url ~ "^/addresses.php" || req.url ~ "^/order-detail.php")) {
      return (pass);
  }
  #we should not cache any page for sales
  if (req.method == "GET" && (req.url ~ "^/order-confirmation.php" || req.url ~ "^/order-return.php")) {
      return (pass);
  }
  if (req.method != "GET" && req.method != "HEAD") {
      return (pass);
  }
  # Remove the "has_js" cookie
  set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");
  # Remove any Google Analytics based cookies
  # set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
  # removes all cookies named __utm? (utma, utmb...) - tracking thing
  set req.http.Cookie = regsuball(req.http.Cookie, "(^|(?<=; )) *__utm.=[^;]+;? *", "\1");
  # Remove a ";" prefix, if present.
  set req.http.Cookie = regsub(req.http.Cookie, "^;\s*", "");
  # Are there cookies left with only spaces or that are empty?
  if (req.http.Cookie ~ "^ *$") {
    unset req.http.Cookie;
  }
  # Cache the following files extensions
  if (req.url ~ "\.(css|js|png|gif|jp(e)?g|swf|ico|woff)") {
    unset req.http.Cookie;
  }
  # Normalize Accept-Encoding header and compression
  # https://www.varnish-cache.org/docs/3.0/tutorial/vary.html
  if (req.http.Accept-Encoding) {
    # Do no compress compressed files...
    if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
          unset req.http.Accept-Encoding;
    } elsif (req.http.Accept-Encoding ~ "gzip") {
          set req.http.Accept-Encoding = "gzip";
    } elsif (req.http.Accept-Encoding ~ "deflate") {
          set req.http.Accept-Encoding = "deflate";
    } else {
      unset req.http.Accept-Encoding;
    }
  }
  # Did not cache HTTP authentication and HTTP Cookie
  if (req.http.Authorization) {
    # Not cacheable by default
    return (pass);
  }
  # Cache all others requests
  return (hash);
}
sub vcl_pipe {
  return (pipe);
}
sub vcl_pass {
  return (fetch);
}
# The data on which the hashing will take place
sub vcl_hash {
  hash_data(req.url);
  # If the client supports compression, keep that in a different cache
  if (req.http.Accept-Encoding) {
    hash_data(req.http.Accept-Encoding);
  }
  
  if (req.http.Cookie) {
     hash_data(req.http.Cookie);
  }
  return (lookup);
}
# This function is used when a request is sent by our backend (Nginx server)
sub vcl_backend_response {
  # Remove some headers we never want to see
  unset beresp.http.Server;
  unset beresp.http.X-Powered-By;
  # For static content strip all backend cookies
  if (bereq.url ~ "\.(css|js|png|gif|jp(e?)g)|swf|ico|woff") {
    unset beresp.http.cookie;
  }
  # Don't store backend
  if (bereq.url ~ "admin70" || bereq.url ~ "preview=true") {
    set beresp.uncacheable = true;
    set beresp.ttl = 30s;
    return (deliver);
  }
  if (bereq.method == "GET" && (bereq.url ~ "^/?mylogout=")) {
    set beresp.ttl = 0s;
    unset beresp.http.Set-Cookie;
    set beresp.uncacheable = true;
    return(deliver);
  }
  # don't cache response to posted requests or those with basic auth
  if ( bereq.method == "POST" || bereq.http.Authorization ) {
          set beresp.uncacheable = true;
    set beresp.ttl = 120s;
    return (deliver);
      }
      # don't cache search results
  if ( bereq.url ~ "\?s=" ){
    set beresp.uncacheable = true;
                set beresp.ttl = 120s;
                return (deliver);
  }
  # only cache status ok
  if ( beresp.status != 200 ) {
    set beresp.uncacheable = true;
                set beresp.ttl = 120s;
                return (deliver);
  }
  # A TTL of 2h
  set beresp.ttl = 2h;
  # Define the default grace period to serve cached content
  set beresp.grace = 30s;
  return (deliver);
}
# The routine when we deliver the HTTP request to the user
# Last chance to modify headers that are sent to the client
sub vcl_deliver {
  if (obj.hits > 0) {
    set resp.http.X-Varnish-Cache = "HIT";
    set resp.http.X-Varnish       = "HIT";
  } else {
    set resp.http.X-Varnish-Cache = "MISS";
    set resp.http.X-Varnish       = "MISS";
  }
  # Remove some headers: PHP version
  unset resp.http.X-Powered-By;
  # Remove some headers: Apache version & OS
  unset resp.http.Server;
  # Remove some heanders: Varnish
  unset resp.http.Via;
  unset resp.http.X-Varnish;
  return (deliver);
}
sub vcl_init {
  return (ok);
}
sub vcl_fini {
  return (ok);
}
