# start_all.sh is used to start all nodes in a "ip" directory
# it will be cp into the "ip" directory
# 定义PID记录文件路径
PID_FILE="./node_pids"
node_dirs=$(find "./" -maxdepth 1 -type d)
for node_dir in $node_dirs; do
    # check node_dir/common_config.json is exist
    if [ -f "$node_dir/common_config.json" ]; then
        nohup ./main --job node --config $node_dir/common_config.json  > $node_dir/log.txt 2>$node_dir/error.txt &
        pid=$!
        echo "$pid" >> "$PID_FILE"
    fi
done
