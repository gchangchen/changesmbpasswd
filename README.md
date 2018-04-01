# changesmbpasswd
change smb password via cgi or scgi.
Use [qs_parse](https://github.com/bartgrantham/qs_parse) for  parsing URL query strings.

## use it as a cgi program.
	sudo cp changesmbpasswd /var/www/cgi-bin/
	sudo chmod u+s /var/www/cgi-bin/changesmbpasswd
browser [http://localhost/cgi-bin/changesmbpasswd](http://localhost/cgi-bin/changesmbpasswd).

## use it as a scgi server.
You can run it:

create a scgi socket listen on port 4000

	sudo changesmbpasswd 4000

or listening on ip and port

	sudo changesmbpasswd 127.0.0.1 4000

or listening on unix local socket.

	sudo changesmbpasswd /tmp/changesmbpasswd.unix.sock

and then set the nginx conf file,and then restart nginx.

	location /changesmbpasswd {
	    include   scgi_params;
	    scgi_pass localhost:4000;
        scgi_param	NGINX_SCGI 1;
	}

or for apache.

	ProxyPass /changesmbpasswd scgi://localhost:4000/

and then browser [http://localhost/changesmbpasswd](http://localhost/changesmbpasswd).

## you also can start it with systemd socket
	
How to compile it 

	make

or use gcc

	gcc -O2 -o changesmbpasswd changesmbpasswd.c qs_parse.c -lsystemd
