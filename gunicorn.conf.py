# gunicorn.conf.py
import multiprocessing
import os

# Bind to port
bind = "0.0.0.0:8000"

# Number of workers
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gevent"
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = "/var/log/rileyfalcon/gunicorn-access.log"
errorlog = "/var/log/rileyfalcon/gunicorn-error.log"
loglevel = "info"

# Process name
proc_name = "rileyfalcon_idps"

# Daemonize
daemon = False

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190