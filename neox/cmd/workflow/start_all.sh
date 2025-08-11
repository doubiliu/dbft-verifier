# start_all.sh is used to start all nodes in a "ip" directory
# it will be cp into the "ip" directory

node_dirs=$(find "./" -maxdepth 1 -type d)
for node_dir in $node_dirs; do
    # check node_dir/common_config.json is exist
    if [ -f "$node_dir/common_config.json" ]; then
        nohup go run main --job node --config $node_dir/common_config.json  > $node_dir/log.txt 2>$node_dir/error.txt &
    fi
done
