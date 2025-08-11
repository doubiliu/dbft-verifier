"""
This script assembles the final, complete configuration for each node.

It reads the network topology from a pre-generated `network.yml` file and
combines it with node-specific parameters (like file paths) from an `instance.yml`
file. Global settings (like pipeline mode) are provided via command-line arguments.

The final, combined configuration file for each node is saved as a JSON file
in a subdirectory named after its IP address.
"""
import sys
import os
import yaml
import argparse
import json

# --- Default Configuration ---
ADDRESS_FILE = "network.yml"
INSTANCE_FILE_DEFAULT = "instance.yml"
OUTPUT_DIR = "configs"

# Shared configuration values
SHARED_GRPC_CONFIG = {
    'MessageLimitSize': 100 * 1024 * 1024,  # 100 MB
    'Timeout': '5s'
}
SHARED_BLOCK_SOURCE = "https://neoxt4seed1.ngd.network/"


def load_yaml_file(file_path, file_description):
    """A generic helper to load and validate a YAML file."""
    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
        if not data or not isinstance(data, dict):
            raise ValueError(f"The {file_description} file must be a non-empty YAML dictionary.")
        print(f"Successfully loaded {file_description} data from '{file_path}'")
        return data
    except FileNotFoundError:
        print(f"Error: {file_description.capitalize()} file '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)
    except (yaml.YAMLError, ValueError) as e:
        print(f"Error parsing or validating {file_description} file: {e}", file=sys.stderr)
        sys.exit(1)


def build_shared_network_config(address_data):
    """Builds the shared NetworkConfig dictionary from the address data."""
    agg_configs = address_data.get('aggregators', [])
    worker_configs = address_data.get('workers', [])

    aggregators_map = {agg['id']: {k: v for k, v in agg.items() if k != 'id'} for agg in agg_configs}
    workers_map = {worker['id']: {k: v for k, v in worker.items() if k != 'id'} for worker in worker_configs}

    return {
        "agg_servers": aggregators_map,
        "worker_servers": workers_map,
        "block_source": SHARED_BLOCK_SOURCE
    }
def generate_manager_config(shared_network_config):
    os.makedirs(OUTPUT_DIR, exist_ok=True)


    # 管理器配置结构：network部分完整保留，其余部分置空
    manager_config = {
        "id": -1,
        "network": shared_network_config,
        "local": {},
    }

    # 保存到configs目录下的manager.json
    output_path = os.path.join(OUTPUT_DIR, "manager.json")
    with open(output_path, 'w') as f:
        json.dump(manager_config, f, indent=4)

    print(f"  -> Generated manager config at '{output_path}'")


def generate_final_configs(address_data, instance_data, args):
    """
    Generates a complete configuration file for each node defined in network.yml.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    shared_network_config = build_shared_network_config(address_data)

    version_map = {"v0": 0, "v1": 1, "v2": 2}
    base_node_config = {
        "mode": 1 if args.pipeline else 0,
        "extra_version": version_map[args.version],
        "nb_solve": 1,
        "nb_prove": 1,
    }

    all_nodes = [('aggregator', agg) for agg in address_data.get('aggregators', [])] + \
                [('worker', w) for w in address_data.get('workers', [])]

    if not all_nodes:
        print("Warning: No aggregators or workers found in the address file. No configs generated.", file=sys.stderr)
        return

    for node_type, node_info in all_nodes:
        node_id = node_info['id']
        node_ip = node_info['address']

        distribute_port = node_info.get('distribute_port')
        aggregate_port = node_info.get('aggregate_port')
        local_url = {'address': node_ip, 'distribute_port': distribute_port, 'aggregate_port': aggregate_port}

        service_config = {
            'id': node_id,
            'network': shared_network_config,
            'local': local_url,
            'grpc_config': SHARED_GRPC_CONFIG
        }

        node_config = base_node_config.copy()
        node_config["job"] = 0 if node_type == 'worker' else 1 # todo manager 2
        node_specific_paths = instance_data.get(node_ip)
        if not node_specific_paths:
            print(f"Warning: No specific path data for IP {node_ip} in '{args.instance}'. NodeConfig may be incomplete.", file=sys.stderr)
        else:
            node_config.update(node_specific_paths)

        final_config = {
            'ServiceConfig': service_config,
            'NodeConfig': node_config
        }

        # --- MODIFICATIONS FOR JSON OUTPUT ---
        ip_specific_dir = os.path.join(OUTPUT_DIR, node_ip)
        # 1. Change file extension to .json
        nodes_dir = os.path.join(ip_specific_dir, f"node_{node_id}")
        os.makedirs(nodes_dir, exist_ok=True)

        output_filename = os.path.join(nodes_dir, "common_config.json")
        with open(output_filename, 'w') as f:
            # 2. Use json.dump for formatted JSON output
            json.dump(final_config, f, indent=4)

        print(f"  -> Generated full config for {node_type} ID {node_id} at '{output_filename}'")
    generate_manager_config(shared_network_config)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Assembles complete node configurations from network.yml and instance.yml into JSON files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # The arguments remain the same
    parser.add_argument("--addresses", default=ADDRESS_FILE,
                        help=f"Path to the pre-generated network topology file.\nDefault: {ADDRESS_FILE}")
    parser.add_argument("--instance", default=INSTANCE_FILE_DEFAULT,
                        help=f"Path to the master file mapping IPs to their specific parameters (e.g., paths).\nDefault: {INSTANCE_FILE_DEFAULT}")
    parser.add_argument("--pipeline", action="store_true",
                        help="Enable Pipeline mode for all nodes. If not present, Serial mode is used.")
    parser.add_argument("--version", default="v1", choices=["v0", "v1", "v2"],
                        help="The 'extra_version' for all nodes.\nDefault: v1")

    args = parser.parse_args()

    try:
        address_data = load_yaml_file(args.addresses, "address")
        instance_data = load_yaml_file(args.instance, "instance")
        generate_final_configs(address_data, instance_data, args)
        print(f"\n✅ All JSON configuration files have been generated in the '{OUTPUT_DIR}' directory.")
    except (ValueError, IOError) as e:
        print(f"\nError: Configuration assembly failed. {e}", file=sys.stderr)
        sys.exit(1)