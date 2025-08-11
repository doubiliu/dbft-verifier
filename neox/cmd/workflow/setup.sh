# we have the instance.yml given by user

# first we build the binary in main.go, and copy into this directory

# we generate the common network config first, then we get network.yml
python3 generate_network_config.py \
    --aggregators 1 \
    --workers 2 \
    --max-agg-per-ip 2 \
    --max-workers-per-ip 3 \
    --distribute-base-port 9000 \
    --aggregate-base-port 10000

# generate configs/...
# then we can use scp to copy dirs to machines
# in the machine which runs this script, we run the Manager
python3 generate_configs.py


# then we copy main into all nodes' dir
# check main is exist
if [ ! -f './main' ]; then
    echo 'main in this directory not found'
    exit 1
fi


node_dirs=$(find ./configs -maxdepth 1 -type d ! -name "manager" ! -name "configs")
for node_dir in $node_dirs; do
    # cp main dir
    if [ -d "$node_dir" ]; then
        echo "copy main into $node_dir"
        cp ./main "$node_dir"
        cp ./start_all.sh "$node_dir"
    fi
done

