import json
import subprocess

# The absolute path to the pre-compiled C binary
# This tool is expected to be installed on the system.
SELF_TOOL_PATH = "/usr/lib/self/self-tool"

def fetch_stats():
    """
    Executes the pre-compiled self-tool binary to fetch all statistics
    and returns them as a Python dictionary.

    The user running this script must have sufficient permissions to execute
    the tool and allow it to read the BPF maps (e.g., run as root).
    """
    try:
        # Run the command: /usr/lib/self/self-tool json-stats
        result = subprocess.run(
            [SELF_TOOL_PATH, "json-stats"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30  #30-second timeout to prevent hangs
        )

        # Parse the JSON output from the C program
        stats = json.loads(result.stdout)
        return stats

    except FileNotFoundError:
        print(f"Error: The binary was not found at '{SELF_TOOL_PATH}'.")
        print("Please ensure that SELF is installed correctly.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error executing '{SELF_TOOL_PATH}':")
        print(f"Return Code: {e.returncode}")
        print(f"Stderr: {e.stderr}")
        print("\nNote: This tool may require root privileges to access BPF maps.")
        return None
    except subprocess.TimeoutExpired:
        print(f"Error: The command '{SELF_TOOL_PATH} json-stats' timed out after 30 seconds.")
        return None
    except json.JSONDecodeError as e:
        print("Error: Failed to parse JSON output from the tool.")
        print(f"JSON Error: {e}")
        print(f"Raw Output received: \n{result.stdout}")
        return None


if __name__ == "__main__":
    all_stats = fetch_stats()

    if all_stats:
        print(json.dumps(all_stats, indent=2)) 