import argparse
import json
import sys
import yaml
def generate_node_config(args):
    """
    Generates node_config.json based on a master paths file and command-line arguments.
    """
    # 1. Read and parse the master paths file
    try:
        with open(args.instance, 'r') as f:
            all_instance_paths = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Master paths file '{args.paths_file}' not found.", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Failed to parse YAML file '{args.paths_file}': {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Find the path configuration for the target IP
    node_specific_paths = all_instance_paths.get(args.ip)

    if not node_specific_paths:
        print(f"Error: IP '{args.ip}' not found in '{args.paths_file}'.", file=sys.stderr)
        sys.exit(1)

    mode = 1 if args.pipeline else 0
    version_map = {
        "v0": 0,
        "v1": 1,
        "v2": 2
    }
    # 3. Build the base configuration dictionary from command-line arguments
    node_config = {
       "mode": mode,
       "extra_version": version_map[args.version]
       "nb_solve": 1,
       "nb_prove": 1,
    }

    # 4. Merge the paths read from the file into the base configuration.
    node_config.update(node_specific_paths)
    # 5. Generate JSON output
    json_output = json.dumps(node_config, indent=2)
    print(json_output)
    #    # 6. Decide whether to print to stdout or write to a file based on the --output argument
    try:
       with open(args.output, 'w') as f:
           f.write(json_output)
       print(f"Successfully generated node config for {args.ip} at '{args.output}'")
    except IOError as e:
       print(f"Error: Could not write to output file '{args.output}': {e}", file=sys.stderr)
       sys.exit(1)
    print(json_output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generates a node_config.json file for a specific node.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("ip",
                        help="The IP address of the target node, used to look up its circuit file paths.")

    parser.add_argument("--instance",
                        default="instance.yml",
                        help="The master configuration file (YAML format) mapping IPs to circuit paths.\nDefault: instance_paths.yml")

    parser.add_argument("--pipeline",
                        action="store_true",
                        help="Enable Pipeline mode. If this flag is not present, Serial mode is used.")

    parser.add_argument("--version",
                        default="v1",
                        choices=["v0", "v1", "v2"],
                        help="The node's Extra Version.\nDefault: v1")

    parser.add_argument("-o", "--output",
                        default="node_config.json",
                        help="Optional: Save the generated configuration to the specified file path.\nIf not provided, prints to standard output.")

    args = parser.parse_args()
    generate_node_config(args)