#!/bin/bash

# ==============================================================================
# Deployment Script
#
# This script automates the process of setting up and deploying the nodes.
# It performs the following steps:
# 1. Parses the --chain argument (defaults to 'n3').
# 2. Builds the Go binary ('main').
# 3. Generates network configuration based on the specified chain.
# 4. Generates individual node configurations.
# 5. Copies the binary and dynamically creates start/stop scripts for each node.
#
# Usage:
#   ./deploy.sh
#   ./deploy.sh --chain my_custom_chain
# ==============================================================================

# --- Step 1: Parse Command-Line Arguments ---
CHAIN_NAME="neox" # Default chain name
rm -rf configs/
# Simple argument parsing
if [ "$1" == "--chain" ] && [ -n "$2" ]; then
    CHAIN_NAME="$2"
fi

echo "Starting deployment for chain: $CHAIN_NAME"


# --- Step 2: Check if the 'main' binary exists
if [ ! -f './main' ]; then
    echo "Error: 'main' binary not found. Build failed or file is missing."
    exit 1
fi


# --- Step 3: Generate Network and Node Configurations ---
echo "Generating network configuration (network.yml)..."
python3 generate_network_config.py \
    --chain "$CHAIN_NAME" \
    --aggregators 1 \
    --workers 2 \
    --max-agg-per-ip 2 \
    --max-workers-per-ip 3 \
    --distribute-base-port 9000 \
    --aggregate-base-port 10000

echo "Generating individual node configs in ./configs/..."
# This script will run the manager in the current machine
python3 generate_configs.py --chain "$CHAIN_NAME"
echo "Configurations generated."


# --- Step 4: Distribute Binary and Scripts to Node Directories ---
echo "Distributing files to node directories..."

# Find all node directories (excluding 'manager' and the parent 'configs' dir)
node_dirs=$(find ./configs -maxdepth 1 -type d ! -name "manager" ! -name "configs")

for node_dir in $node_dirs; do
    if [ -d "$node_dir" ]; then
        echo "Processing directory: $node_dir"

        # Copy the main binary
        echo "  -> Copying binary 'main'..."
        cp ./main "$node_dir"

        # Create start_all.sh dynamically
        echo "  -> Creating 'start_all.sh'..."
        cat > "$node_dir/start_all.sh" << EOF
#!/bin/bash
# start_all.sh is used to start all nodes in this IP's directory.
# This script is auto-generated.

# Path to the PID file for tracking running processes
PID_FILE="./node_pids"

# Clear any old PID file before starting
echo "Initializing PID file..." > "\$PID_FILE"

echo "Starting all nodes in this directory..."
# Find all subdirectories that contain a common_config.json
node_subdirs=\$(find "./" -maxdepth 1 -type d)

for sub_dir in \$node_subdirs; do
    # Check if the configuration file exists
    if [ -f "\$sub_dir/common_config.json" ]; then
        echo "  -> Starting node in \$sub_dir"
        # Start the node process in the background
        # Note: We run ./main from the parent directory of sub_dir
        nohup ./main --job node --config "\$sub_dir/common_config.json" --chain $CHAIN_NAME > "\$sub_dir/log.txt" 2> "\$sub_dir/error.txt" &

        # Capture the process ID (PID) of the last background command
        pid=\$!
        echo "     Started with PID: \$pid"

        # Append the PID to our tracking file
        echo "\$pid" >> "\$PID_FILE"
    fi
done

echo "✅ All nodes started."
EOF

        # Create stop_all.sh dynamically
        echo "  -> Creating 'stop_all.sh'..."
        cat > "$node_dir/stop_all.sh" << EOF
#!/bin/bash
# stop_all.sh is used to stop all nodes started by start_all.sh.
# This script is auto-generated.

PID_FILE="./node_pids"

if [ ! -f "\$PID_FILE" ]; then
    echo "Warning: PID file (\$PID_FILE) not found. Nothing to stop."
    exit 1
fi

echo "Stopping all nodes managed by this script..."
while IFS= read -r pid; do
    # Ensure the line is not empty
    if [ -n "\$pid" ]; then
        echo "  -> Attempting to stop process with PID: \$pid"
        # Use kill command to send a TERM signal. The '2>/dev/null' suppresses errors if the process is already gone.
        if kill "\$pid" 2>/dev/null; then
            echo "     Successfully sent stop signal to PID \$pid."
        else
            echo "     Warning: Process with PID \$pid not found. It might have already stopped."
        fi
    fi
done < "\$PID_FILE"

# Clean up the PID file after stopping all processes
rm -f "\$PID_FILE"

echo "✅ Stop script finished."
EOF

        # Make the new scripts executable
        echo "  -> Setting execute permissions..."
        chmod +x "$node_dir/start_all.sh"
        chmod +x "$node_dir/stop_all.sh"
    fi
done

echo "Setup process completed successfully!"