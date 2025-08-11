PID_FILE="./node_pids"
if [ ! -f "$PID_FILE" ]; then
        echo "$PID_FILE not found"
        exit 1
fi

echo "stop all nodes..."
while IFS= read -r pid; do
    if [ -n "$pid" ]; then
        echo "stop process (PID: $pid)"
        if kill "$pid" 2>/dev/null; then
            echo "  stop process $pid successfully"
        else
            echo "  warning：process $pid has been stopped or not exist"
        fi
    fi
done < "$PID_FILE"

rm -f "$PID_FILE"
echo "finish stop all nodes"