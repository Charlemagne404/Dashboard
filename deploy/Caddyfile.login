login.continental-hub.com {
	handle /api/health {
		reverse_proxy 127.0.0.1:5000
	}

	handle /api/auth/* {
		reverse_proxy 127.0.0.1:5000
	}

	handle /api/grimoire/* {
		reverse_proxy 127.0.0.1:5000
	}

	root * /var/www/continental-id-login
	try_files {path} /index.html
	file_server
}
