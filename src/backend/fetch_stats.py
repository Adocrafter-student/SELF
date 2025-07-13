#!/usr/bin/env python3
import json
import subprocess
import time
import requests
import os
import logging
import logging.handlers
import sys

# Paths
#Path on the frontend  REACT_APP_API_URL=http://<your-python-server-ip>:5000 npm start
SELF_TOOL_PATH = "/usr/lib/self/self-tool"
CONFIG_PATH = "/etc/self/server.conf"
LOG_FILE = "/var/log/self-stats.log"
INITIAL_DELAY = 30

# Configure logger
logger = logging.getLogger("self_stats")
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=5*1024*1024, backupCount=3
)
formatter = logging.Formatter(
    '%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)
logger.addHandler(handler)


def get_config():
    """Parses the server.conf file to get server URL and interval."""
    config = {'server': None, 'timeInSeconds': 300}  # Default 5 minutes
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or ':' not in line:
                    continue
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip()

    server_ip = config.get('server')
    server_url = f"http://{server_ip}:5000/api/data" if server_ip else None

    try:
        config['timeInSeconds'] = int(config.get('timeInSeconds', 300))
    except ValueError:
        logger.warning("Invalid timeInSeconds in config; defaulting to 300")
        config['timeInSeconds'] = 300

    return server_url, config['timeInSeconds']


def send_stats(server_url, stats):
    """Sends stats to the server via POST request."""
    if not server_url:
        logger.error("Server URL not configured. Cannot send stats.")
        return False

    try:
        headers = {'Content-Type': 'application/json'}
        payload = json.dumps(stats)
        logger.debug("Sending payload: %s", payload)
        response = requests.post(server_url, data=payload, headers=headers, timeout=10)
        response.raise_for_status()
        logger.info("Successfully sent stats to %s", server_url)
        return True
    except requests.exceptions.RequestException as e:
        logger.error("Error sending stats to %s: %s", server_url, e)
        return False


def fetch_stats():
    """
    Executes the pre-compiled self-tool binary to fetch all statistics
    and returns them as a Python dictionary.
    """
    try:
        result = subprocess.run(
            [SELF_TOOL_PATH, "json-stats"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        stats = json.loads(result.stdout)
        logger.debug("Fetched stats: %s", json.dumps(stats))
        return stats

    except FileNotFoundError:
        logger.error("Binary not found at '%s'. Ensure SELF is installed correctly.", SELF_TOOL_PATH)
    except subprocess.CalledProcessError as e:
        logger.error(
            "Error executing '%s': returncode=%d, stderr=%s",
            SELF_TOOL_PATH, e.returncode, e.stderr.strip()
        )
        logger.error("This tool may require root privileges to access BPF maps.")
    except subprocess.TimeoutExpired:
        logger.error("Command '%s json-stats' timed out after 30 seconds.", SELF_TOOL_PATH)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse JSON from tool output: %s", e)
        logger.debug("Raw output: %s", getattr(e, 'doc', ''))
    return None


def main():
    server_url, interval = get_config()
    logger.info("Waiting for %d seconds before starting...", INITIAL_DELAY)
    time.sleep(INITIAL_DELAY)
    if not server_url:
        logger.critical("Server not configured in %s; exiting.", CONFIG_PATH)
        sys.exit(1)

    logger.info("Starting self-stats sender (interval=%ds) to %s", interval, server_url)
    while True:
        stats = fetch_stats()
        if stats is not None:
            send_stats(server_url, stats)
        else:
            logger.debug("No stats to send this cycle.")
        logger.debug("Sleeping for %d seconds...", interval)
        time.sleep(interval)


if __name__ == "__main__":
    main()
