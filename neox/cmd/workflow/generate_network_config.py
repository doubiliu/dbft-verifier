"""
This script generates an address.yml
    based on the instance.xml provided by the user (including the IP address of the machine),
    as well as specifying the number of aggregators and workers (a limit can be given for each machine),
    which includes the addresses of the aggregators and workers for use in subsequent scripts.
    It can be modified.
"""

import sys
from collections import defaultdict
import yaml
import itertools

# Point to your new YAML config file
IP_CONFIG_FILE = "instance.yml"
OUTPUT_YAML_FILE = "network.yml"

# Total number of processes to create
NB_AGGREGATORS = 2
NB_WORKERS = 3

# Capacity constraints per IP address
MAX_AGGREGATORS_PER_IP = 2
MAX_WORKERS_PER_IP = 3

# --- MODIFIED: Base ports for each role and port type ---
DISTRIBUTE_BASE_PORT = 9000
AGGREGATE_BASE_PORT = 10000 # Use a separate range for the second port

def get_ips_from_config(config_path):
    """
    Reads a YAML config file and extracts the top-level keys as IP addresses.
    (This function remains unchanged)
    """
    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)

        if not config_data or not isinstance(config_data, dict):
            print(f"Error: Config file '{config_path}' is empty or not a valid IP-keyed dictionary.")
            sys.exit(1)

        ips = list(config_data.keys())
        print(f"Found {len(ips)} IP(s) in '{config_path}': {ips}")
        return ips

    except FileNotFoundError:
        print(f"Error: IP config file '{config_path}' not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file '{config_path}': {e}")
        sys.exit(1)

# --- NEW FUNCTION for Aggregators ---
def distribute_aggregators(total_needed, ips, max_per_ip, dist_base_port, agg_base_port, id_generator):
    """
    Distributes aggregators across IPs, assigning an address and two distinct ports.
    """
    if not ips:
        raise ValueError("Cannot distribute Aggregators: The provided IP list is empty.")

    total_capacity = len(ips) * max_per_ip
    if total_needed > total_capacity:
        raise ValueError(
            f"Cannot create {total_needed} Aggregators. "
            f"The available {len(ips)} IPs with a max of {max_per_ip} per IP "
            f"only support a total of {total_capacity}."
        )

    processes = []
    ip_usage_counts = defaultdict(int)
    ip_iterator = 0

    for i in range(total_needed):
        process_id = next(id_generator)
        while True:
            current_ip = ips[ip_iterator % len(ips)]
            if ip_usage_counts[current_ip] < max_per_ip:
                ip_usage_counts[current_ip] += 1

                # Assign two separate ports for each aggregator
                dist_port = dist_base_port + i
                agg_port = agg_base_port + i

                processes.append({
                    'id': process_id,
                    'address': current_ip,
                    'distribute_port': dist_port,
                    'aggregate_port': agg_port
                })

                ip_iterator += 1
                break
            else:
                ip_iterator += 1
    return processes

# --- NEW FUNCTION for Workers ---
def distribute_workers(total_needed, ips, max_per_ip, dist_base_port, id_generator):
    """
    Distributes workers across IPs, assigning an address (IP) and a port.
    """
    if not ips:
        raise ValueError("Cannot distribute Workers: The provided IP list is empty.")

    total_capacity = len(ips) * max_per_ip
    if total_needed > total_capacity:
        raise ValueError(
            f"Cannot create {total_needed} Workers. "
            f"The available {len(ips)} IPs with a max of {max_per_ip} per IP "
            f"only support a total of {total_capacity}."
        )

    processes = []
    ip_usage_counts = defaultdict(int)
    ip_iterator = 0

    for i in range(total_needed):
        process_id = next(id_generator)
        while True:
            current_ip = ips[ip_iterator % len(ips)]
            if ip_usage_counts[current_ip] < max_per_ip:
                ip_usage_counts[current_ip] += 1

                dist_port = dist_base_port + i

                processes.append({
                    'id': process_id,
                    'address': current_ip, # 'address' field now holds only the IP
                    'distribute_port': dist_port,
                    "aggregate_port": -1,
                })

                ip_iterator += 1
                break
            else:
                ip_iterator += 1
    return processes


if __name__ == "__main__":
    # 1. Get the list of IPs from the new YAML config file
    all_ips = get_ips_from_config(IP_CONFIG_FILE)

    try:
        # 2. To maximize separation, use normal list for aggregators and reversed for workers
        aggregator_ips = all_ips
        worker_ips = all_ips[::-1]

        # Create a single ID counter for all processes
        id_counter = itertools.count()

        # 3. Generate addresses using the new specific functions
        agg_configs = distribute_aggregators(
            NB_AGGREGATORS, aggregator_ips, MAX_AGGREGATORS_PER_IP,
            DISTRIBUTE_BASE_PORT, AGGREGATE_BASE_PORT, id_counter
        )
        worker_configs = distribute_workers(
            NB_WORKERS, worker_ips, MAX_WORKERS_PER_IP, DISTRIBUTE_BASE_PORT + NB_AGGREGATORS, id_counter
        )

        # 4. Print results to the console with the new format
        print(f"\n--- Aggregator Configurations ({len(agg_configs)}) ---")
        for agg in agg_configs:
            print(f"  ID: {agg['id']:<3} Address: {agg['address']:<15} Distribute Port: {agg['distribute_port']:<5} Aggregate Port: {agg['aggregate_port']}")

        print(f"\n--- Worker Configurations ({len(worker_configs)}) ---")
        for worker in worker_configs:
            print(f"  ID: {worker['id']:<3} Address: {worker['address']:<15} Port: {worker['distribute_port']}")

        # 5. Structure the data for YAML output
        output_data = {
            'aggregators': agg_configs,
            'workers': worker_configs
        }

        # 6. Write the structured data to the output YAML file
        with open(OUTPUT_YAML_FILE, 'w') as f:
            yaml.dump(output_data, f, default_flow_style=False, sort_keys=False)

        print(f"\n✅ Successfully saved addresses to '{OUTPUT_YAML_FILE}'")


    except ValueError as e:
        print(f"\nError: Configuration failed. {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)