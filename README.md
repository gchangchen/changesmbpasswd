# changesmbpasswd
change smb password via web server.
Use [picohttpparser](https://github.com/h2o/picohttpparser) for  parsing http request.
Use [qs_parse](https://github.com/bartgrantham/qs_parse) for  parsing URL query strings.

## use it as a cgi program.
	sudo cp changesmbpasswd /var/www/cgi-bin/
	sudo chmod u+s /var/www/cgi-bin/changesmbpasswd
browser [http://localhost/cgi-bin/changesmbpasswd](http://localhost/cgi-bin/changesmbpasswd).

## use it as a scgi or http server.
### start it Manually
create a server listen on port 4000

	sudo changesmbpasswd -p 4000

or listening on ip and port

	sudo changesmbpasswd -l 127.0.0.1 -p 4000

when the server started, both scgi and http protocal are valid.
You can browser [http://localhost:4000/](http://localhost:4000/) to use it.

or as a scgi server.then set the nginx conf file,and then restart nginx.

	location /changesmbpasswd {
	    include   scgi_params;
	    scgi_pass localhost:4000;
        scgi_param	NGINX_SCGI 1;
	}

or for apache.

	ProxyPass /changesmbpasswd scgi://localhost:4000/

and then browser [http://localhost/changesmbpasswd](http://localhost/changesmbpasswd).

### you also can install it as a systemd servers.
#### install
	sudo cp changesmbpasswd /usr/local/bin/
	sudo cp changesmbpasswd.service /etc/systemd/system/
	sudo cp changesmbpasswd@.service /etc/systemd/system/
	sudo cp changesmbpasswd.socket /etc/systemd/system/
	sudo systemctl daemon-reload
#### start it.
	sudo systemctl start changesmbpasswd
or use systemd socket
	sudo systemctl start changesmbpasswd.socket

#### start it from boot automatic.
	sudo systemctl enable changesmbpasswd.socket
	
## How to compile it 
	make

or use gcc

	gcc -O2 -o changesmbpasswd changesmbpasswd.c qs_parse.c picohttpparser.c -ldl
