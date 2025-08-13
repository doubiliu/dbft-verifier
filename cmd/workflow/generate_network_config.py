import sys
import argparse
from collections import defaultdict
import yaml
import itertools

# Default config file paths
IP_CONFIG_FILE = "instance.yml"
OUTPUT_YAML_FILE = "network.yml"

def get_ips_from_config(config_path):
    """
    Reads a YAML config file and extracts the top-level keys as IP addresses.
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
                    'address': current_ip,  # 'address' field now holds only the IP
                    'distribute_port': dist_port,
                    "aggregate_port": -1,
                })

                ip_iterator += 1
                break
            else:
                ip_iterator += 1
    return processes


if __name__ == "__main__":
    # Set up command line argument parser
    parser = argparse.ArgumentParser(description='Generates YAML file with aggregator and worker addresses')
    
    # Add command line arguments
    parser.add_argument('--aggregators', type=int, required=True,
                      help='Total number of aggregators to create')
    parser.add_argument('--workers', type=int, required=True,
                      help='Total number of workers to create')
    parser.add_argument('--max-agg-per-ip', type=int, required=True, 
                      help='Maximum number of aggregators allowed per IP address')
    parser.add_argument('--max-workers-per-ip', type=int, required=True, 
                      help='Maximum number of workers allowed per IP address')
    parser.add_argument('--distribute-base-port', type=int, required=True, 
                      help='Base port number for distribute ports')
    parser.add_argument('--aggregate-base-port', type=int, required=True, 
                      help='Base port number for aggregate ports')
    parser.add_argument('--input', type=str, default=IP_CONFIG_FILE, 
                      help=f'Path to input IP config file (default: {IP_CONFIG_FILE})')
    parser.add_argument('--output', type=str, default=OUTPUT_YAML_FILE, 
                      help=f'Path to output network config file (default: {OUTPUT_YAML_FILE})')
    
    # Parse command line arguments
    args = parser.parse_args()

    # 1. Get the list of IPs from the config file
    all_ips = get_ips_from_config(args.input)

    try:
        # 2. To maximize separation, use normal list for aggregators and reversed for workers
        aggregator_ips = all_ips
        worker_ips = all_ips[::-1]

        # Create a single ID counter for all processes
        id_counter = itertools.count()

        # 3. Generate addresses using the specific functions
        agg_configs = distribute_aggregators(
            args.aggregators, aggregator_ips, args.max_agg_per_ip,
            args.distribute_base_port, args.aggregate_base_port, id_counter
        )
        worker_configs = distribute_workers(
            args.workers, worker_ips, args.max_workers_per_ip, 
            args.distribute_base_port + args.aggregators, id_counter
        )

        # 4. Print results to the console
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
        with open(args.output, 'w') as f:
            yaml.dump(output_data, f, default_flow_style=False, sort_keys=False)

        print(f"\n✅ Successfully saved addresses to '{args.output}'")


    except ValueError as e:
        print(f"\nError: Configuration failed. {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)
