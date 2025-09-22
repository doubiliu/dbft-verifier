# Workflow Deployment Scripts

This directory contains scripts and configuration files for automated deployment and management of distributed zero-knowledge proof verification nodes for Neo N3 and NeoX blockchains.

## Overview

The workflow system automates the deployment of a distributed network consisting of:
- **Workers**: Nodes that perform zero-knowledge proof computations
- **Aggregators**: Nodes that aggregate results from workers (NeoX only)
- **Manager**: Central coordination node

## Files Description

### Scripts

#### `setup.sh`
Main deployment script that orchestrates the entire setup process.

**Usage:**
```bash
./setup.sh [--chain <chain_name>]
```

**Parameters:**
- `--chain`: Target blockchain (default: "neox")
    - `neox`: NeoX blockchain with aggregators and workers
    - `n3`: Neo N3 blockchain with workers only

**What it does:**
1. Builds the Go binary (`main`)
2. Generates network configuration using Python scripts
3. Creates individual node configurations
4. Distributes binaries and creates start/stop scripts for each node

**Example:**
```bash
# Deploy for NeoX (default)
./setup.sh

# Deploy for Neo N3
./setup.sh --chain n3 --network <network id>
```

#### `generate_network_config.py`
Generates the network topology configuration file (`network.yml`).

**Usage:**
```bash
python3 generate_network_config.py --chain <chain> --workers <num> --max-workers-per-ip <max> --distribute-base-port <port> [neox-specific-options]
```

**Common Parameters:**
- `--chain`: Chain type (`neox` or `n3`)
- `--workers`: Total number of worker nodes
- `--max-workers-per-ip`: Maximum workers per IP address
- `--distribute-base-port`: Base port for distribute services

**NeoX-specific Parameters:**
- `--aggregators`: Total number of aggregator nodes
- `--max-agg-per-ip`: Maximum aggregators per IP address
- `--aggregate-base-port`: Base port for aggregate services

**Examples:**

For NeoX:
```bash
python3 generate_network_config.py \
    --chain neox \
    --aggregators 1 \
    --workers 2 \
    --max-agg-per-ip 2 \
    --max-workers-per-ip 3 \
    --distribute-base-port 9000 \
    --aggregate-base-port 10000
```

For Neo N3:
```bash
python3 generate_network_config.py \
    --chain n3 \
    --workers 3 \
    --max-workers-per-ip 2 \
    --distribute-base-port 9000
```

#### `generate_configs.py`
Assembles complete node configurations by combining network topology with instance-specific parameters.

**Usage:**
```bash
python3 generate_configs.py --chain <chain> [options]
```

**Parameters:**
- `--chain`: Chain type (`neox` or `n3`)
- `--addresses`: Network topology file (default: `network.yml`)
- `--instance`: Instance configuration file (default: `instance.yml`)
- `--pipeline`: Enable pipeline mode (default: serial mode)
- `--version`: Extra version for circuits (`v0`, `v1`, `v2`, default: `v1`)

**Examples:**
```bash
# Generate configs for NeoX with pipeline mode
python3 generate_configs.py --chain neox --pipeline --version v1

# Generate configs for Neo N3
python3 generate_configs.py --chain n3 --version v1
```

### Configuration Files

#### `instance.yml`
Defines the absolute paths to circuit files for each IP address. **This file must be manually configured** before deployment.

**Structure:**
```yaml
<ip_address>:
  rlp_hash_instance:
    ccs_path: "/path/to/rlp_encode_hash_extra_v1_test.ccs"
    pk_path: "/path/to/rlp_encode_hash_extra_v1_test.pk"
    vk_path: "/path/to/rlp_encode_hash_extra_v1_test.vk"
  to_g2_hash_instance:
    ccs_path: "/path/to/to_g2_hash.ccs"
    pk_path: "/path/to/to_g2_hash.pk"
    vk_path: "/path/to/to_g2_hash.vk"
  neox_outer_instance:
    ccs_path: "/path/to/verify_header_extra_v1.ccs"
    pk_path: "/path/to/verify_header_extra_v1.pk"
    vk_path: "/path/to/verify_header_extra_v1.vk"
  n3_verifier_instance:
    ccs_path: "/path/to/verifier_header.ccs"
    pk_path: "/path/to/verifier_header.pk"
    vk_path: "/path/to/verifier_header.vk"
```

**Circuit Instances:**
- `rlp_hash_instance`: RLP encoding and hash verification circuit
- `to_g2_hash_instance`: Hash to G2 point conversion circuit
- `no_sig_rlp_instance`: RLP encoding without signature verification
- `neox_outer_instance`: NeoX outer aggregation circuit
- `n3_verifier_instance`: Neo N3 header verification circuit

#### `network.yml`
Generated network topology file containing node addresses and ports.

**Structure:**
```yaml
workers:
  - id: 1
    address: localhost
    distribute_port: 9001
    aggregate_port: -1
  - id: 2
    address: localhost
    distribute_port: 9002
    aggregate_port: -1

aggregators:  # Only for NeoX
  - id: 0
    address: localhost
    distribute_port: 9000
    aggregate_port: 10000
```

## Deployment Workflow

### Prerequisites

1. **Build the main binary:**
   ```bash
   cd /path/to/project/root
   go build -o main main.go
   ```

2. **Configure instance.yml:**
    - Update all file paths to match your deployment environment
    - Ensure all circuit files (`.ccs`, `.pk`, `.vk`) are available at specified paths

3. **Install Python dependencies:**
   ```bash
   pip3 install pyyaml
   ```

### Step-by-Step Deployment

#### For NeoX Deployment

1. **Configure instance paths:**
   ```bash
   # Edit instance.yml with correct file paths
   vim instance.yml
   ```

2. **Run deployment:**
   ```bash
   ./setup.sh --chain neox
   ```

3. **Start nodes:**
   ```bash
   # Start all nodes on each IP
   cd configs/<ip_address>
   ./start_all.sh
   ```

4. **Monitor logs:**
   ```bash
   # Check logs for each node
   tail -f configs/<ip>/node_<id>/log.txt
   tail -f configs/<ip>/node_<id>/error.txt
   ```

5. **Stop nodes:**
   ```bash
   cd configs/<ip_address>
   ./stop_all.sh
   ```

#### For Neo N3 Deployment

1. **Configure instance paths:**
   ```bash
   # Edit instance.yml with N3-specific paths
   vim instance.yml
   ```

2. **Run deployment:**
   ```bash
   ./setup.sh --chain n3 --network 894710606
   ```

3. **Start and manage nodes** (same as NeoX)

### Generated Directory Structure

After running the deployment scripts, the following structure is created:

```
configs/
├── manager.json                    # Manager configuration
├── <ip1>/
│   ├── main                       # Binary executable
│   ├── start_all.sh              # Start script for all nodes on this IP
│   ├── stop_all.sh               # Stop script for all nodes on this IP
│   ├── node_pids                 # PID tracking file
│   ├── node_<id1>/
│   │   ├── common_config.json    # Node configuration
│   │   ├── log.txt              # Node output log
│   │   └── error.txt            # Node error log
│   └── node_<id2>/
│       ├── common_config.json
│       ├── log.txt
│       └── error.txt
└── <ip2>/
    └── ... (similar structure)
```

## Configuration Parameters

### Node Configuration

Each node's `common_config.json` contains:

```json
{
  "ServiceConfig": {
    "id": 0,
    "network": {
      "agg_servers": {...},
      "worker_servers": {...},
      "block_source": "https://neoxt4seed1.ngd.network/"
    },
    "local": {
      "address": "localhost",
      "distribute_port": 9000,
      "aggregate_port": 10000
    },
    "grpc_config": {
      "MessageLimitSize": 104857600,
      "Timeout": "5s"
    }
  },
  "NodeConfig": {
    "job": 1,
    "mode": 1,
    "extra_version": 1,
    "nb_solve": 1,
    "nb_prove": 1,
    "rlp_hash_instance": {...},
    "to_g2_hash_instance": {...},
    "neox_outer_instance": {...},
    "n3_verifier_instance": {...}
  }
}
```

### Key Parameters

- **job**: Node type (0=worker, 1=aggregator, 2=manager)
- **mode**: Processing mode (0=serial, 1=pipeline)
- **extra_version**: Circuit version (0=v0, 1=v1, 2=v2)
- **nb_solve**: Number of solver threads
- **nb_prove**: Number of prover threads

### Block Sources

- **NeoX**: `https://neoxt4seed1.ngd.network/`
- **Neo N3**: `http://seed5t5.neo.org:20332`

## Troubleshooting

### Common Issues

1. **Binary not found:**
   ```bash
   # Ensure main binary is built in project root
   go build -o main main.go
   ```

2. **Python dependencies missing:**
   ```bash
   pip3 install pyyaml
   ```

3. **Port conflicts:**
    - Check if ports are already in use
    - Modify base port numbers in generation scripts

4. **File path errors:**
    - Verify all paths in `instance.yml` are correct
    - Ensure circuit files exist at specified locations

5. **Permission errors:**
   ```bash
   # Make scripts executable
   chmod +x setup.sh
   chmod +x configs/*/start_all.sh
   chmod +x configs/*/stop_all.sh
   ```

### Log Analysis

- **Node logs**: `configs/<ip>/node_<id>/log.txt`
- **Error logs**: `configs/<ip>/node_<id>/error.txt`
- **Process tracking**: `configs/<ip>/node_pids`

### Manual Node Management

Start individual node:
```bash
cd configs/<ip>
nohup ./main --job node --config node_<id>/common_config.json --chain <chain> > node_<id>/log.txt 2> node_<id>/error.txt &
```

Stop individual node:
```bash
kill <pid>
```

## Advanced Configuration

### Custom Network Topology

To create custom network configurations:

1. Modify `instance.yml` with your IP addresses and paths
2. Run `generate_network_config.py` with custom parameters
3. Run `generate_configs.py` to create final configurations

### Multi-Machine Deployment

1. Configure `instance.yml` with multiple IP addresses
2. Ensure all machines have the required circuit files
3. Copy generated configs to respective machines
4. Run start scripts on each machine

### Performance Tuning

- Adjust `nb_solve` and `nb_prove` based on hardware capabilities
- Use pipeline mode (`--pipeline`) for better throughput
- Monitor resource usage and adjust node distribution accordingly