#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generates network addresses for aggregators and workers based on an IP list file
and capacity constraints per machine.

Strategy:
1.  Read a list of IP addresses from a file.
2.  Check if there is enough total capacity across all IPs to host the requested
    number of aggregators and workers.
3.  To maximize separation, assign aggregators starting from the first IP
    and workers starting from the last IP.
4.  Distribute processes in a round-robin fashion, respecting the maximum
    number of processes allowed on each IP.
"""

import sys
from collections import defaultdict

# --- Configuration (can be modified as needed) ---
IP_LIST_FILE = "ip_lists"

# Total number of processes to create
NB_AGGREGATORS = 2
NB_WORKERS = 3

# Capacity constraints per IP address
MAX_AGGREGATORS_PER_IP = 2
MAX_WORKERS_PER_IP = 3

# Base ports for each role to avoid conflicts on the same machine
AGGREGATOR_BASE_PORT = 9000
WORKER_BASE_PORT = 10000

def get_ips(ip_list_path):
    """Reads an IP list from a file and removes empty or whitespace-only lines."""
    try:
        with open(ip_list_path, 'r') as f:
            ips = list(filter(None, [line.strip() for line in f.readlines()]))
        return ips
    except FileNotFoundError:
        print(f"Error: IP list file '{ip_list_path}' not found.")
        sys.exit(1)

def distribute_addresses(total_needed, ips, max_per_ip, base_port, role_name):
    """
    Distributes a number of processes across a list of IPs with capacity limits.

    Args:
        total_needed (int): The total number of processes to assign.
        ips (list): The list of IP addresses to use.
        max_per_ip (int): The maximum number of processes allowed on a single IP.
        base_port (int): The starting port number.
        role_name (str): The name of the role (e.g., "Aggregator") for logging.

    Returns:
        list: A list of generated 'ip:port' addresses.
    """
    if not ips:
        raise ValueError("Cannot distribute processes: The provided IP list is empty.")

    # 1. Feasibility Check: Is there enough capacity overall?
    total_capacity = len(ips) * max_per_ip
    if total_needed > total_capacity:
        raise ValueError(
            f"Cannot create {total_needed} {role_name}(s). "
            f"The available {len(ips)} IPs with a max of {max_per_ip} per IP "
            f"only support a total of {total_capacity} {role_name}(s)."
        )

    addresses = []
    # defaultdict(int) will initialize new keys with a value of 0.
    ip_usage_counts = defaultdict(int)
    ip_iterator = 0

    # 2. Assign processes one by one
    for i in range(total_needed):
        # Find the next available IP slot using a round-robin approach
        while True:
            current_ip = ips[ip_iterator % len(ips)]
            if ip_usage_counts[current_ip] < max_per_ip:
                # Found a slot on this IP
                ip_usage_counts[current_ip] += 1
                port = base_port + i
                addresses.append(f"{current_ip}:{port}")
                ip_iterator += 1
                break # Move to assign the next process
            else:
                # This IP is full, check the next one in the list
                ip_iterator += 1

    return addresses

# --- Main execution block ---
if __name__ == "__main__":
    # 1. Get the list of IPs
    all_ips = get_ips(IP_LIST_FILE)

    print("--- System Configuration ---")
    print(f"Available IPs: {all_ips}")
    print(f"Total Aggregators to create: {NB_AGGREGATORS} (max {MAX_AGGREGATORS_PER_IP} per IP)")
    print(f"Total Workers to create: {NB_WORKERS} (max {MAX_WORKERS_PER_IP} per IP)")

    try:
        # 2. To maximize separation, aggregators use the IP list as is,
        #    while workers use a reversed version of the list.
        aggregator_ips = all_ips
        worker_ips = all_ips[::-1] # A reversed copy of the list

        # 3. Generate addresses for each role
        agg_addrs = distribute_addresses(
            NB_AGGREGATORS, aggregator_ips, MAX_AGGREGATORS_PER_IP, AGGREGATOR_BASE_PORT, "Aggregator"
        )
        worker_addrs = distribute_addresses(
            NB_WORKERS, worker_ips, MAX_WORKERS_PER_IP, WORKER_BASE_PORT, "Worker"
        )

        # 4. Print the results
        print("\n" + "="*40)
        print("      Generated Address Configuration")
        print("="*40)

        print(f"\n--- Aggregator Addresses ({len(agg_addrs)}) ---")
        for addr in agg_addrs:
            print(addr)

        print(f"\n--- Worker Addresses ({len(worker_addrs)}) ---")
        for addr in worker_addrs:
            print(addr)

        print("\n" + "="*40)

    except ValueError as e:
        # Catch configuration or capacity errors
        print(f"\nError: Configuration failed. {e}")
        sys.exit(1)