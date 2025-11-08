#!/bin/bash

API_BASE="http://localhost:8080"

ACTION=${1:-status}

case $ACTION in
    status)
        echo "=== WireGuard Status ==="
        curl -s $API_BASE/status | jq .
        ;;
    connect)
        echo "=== Connecting WireGuard ==="
        curl -s -X POST $API_BASE/connect | jq .
        ;;
    disconnect)
        echo "=== Disconnecting WireGuard ==="
        curl -s -X POST $API_BASE/disconnect | jq .
        ;;
    config)
        echo "=== Current Configuration ==="
        curl -s $API_BASE/config | jq .
        ;;
    generate-keys)
        SAVE_TO_ENV=${2:-false}
        echo "=== Generating New WireGuard Keys ==="
        curl -s -X POST $API_BASE/keys/generate \
            -H "Content-Type: application/json" \
            -d "{\"save_to_env\": $SAVE_TO_ENV}" | jq .
        ;;
    current-keys)
        echo "=== Current Keys ==="
        curl -s $API_BASE/keys/current | jq .
        ;;
    private-key)
        echo "=== Generate Private Key (Multiple Formats) ==="
        curl -s -X POST $API_BASE/keys/private | jq .
        ;;
    private-key-simple)
        echo "=== Generate Private Key (Simple Text) ==="
        curl -s -X POST $API_BASE/keys/private/simple
        ;;
    private-key-env)
        echo "=== Generate Private Key (Env Format) ==="
        curl -s -X POST $API_BASE/keys/private/env
        ;;
    public-key-simple)
        echo "=== Generate Public Key from Current Private Key ==="
        curl -s -X POST $API_BASE/keys/public/simple
        ;;
    health)
        echo "=== Health Check ==="
        curl -s $API_BASE/health | jq .
        ;;
    debug-endpoint)
        echo "=== Endpoint Debug ==="
        curl -s $API_BASE/debug/endpoint | jq .
        ;;
    debug-network)
        echo "=== Network Debug ==="
        curl -s $API_BASE/debug/network | jq .
        ;;
    debug-keys)
        echo "=== Keys Debug ==="
        curl -s $API_BASE/debug/keys | jq .
        ;;
    debug-iptables)
        echo "=== iptables Debug ==="
        curl -s $API_BASE/debug/iptables | jq .
        ;;
    debug-resolve)
        echo "=== DNS Resolution Debug ==="
        curl -s $API_BASE/debug/resolve | jq .
        ;;
    debug-routes)
        echo "=== Routing Debug ==="
        curl -s $API_BASE/debug/routes | jq .
        ;;
    logs)
        echo "=== Container Logs ==="
        docker logs wireguard-go-app -f
        ;;
    setup)
        echo "=== Full Setup: Generate Keys and Save to .env ==="
        curl -s -X POST $API_BASE/keys/generate \
            -H "Content-Type: application/json" \
            -d '{"save_to_env": true}' | jq .

        echo -e "\n=== Current Configuration ==="
        curl -s $API_BASE/config | jq .
        ;;
    quick-connect)
        echo "=== Quick Connect Setup ==="
        echo "1. Generating keys..."
        curl -s -X POST $API_BASE/keys/generate \
            -H "Content-Type: application/json" \
            -d '{"save_to_env": true}' | jq .

        echo -e "\n2. Connecting WireGuard..."
        curl -s -X POST $API_BASE/connect | jq .

        echo -e "\n3. Final Status:"
        curl -s $API_BASE/status | jq .
        ;;
    # New commands for client modes
    mode-share)
        echo "=== Switching to SHARE mode ==="
        echo "Use this mode to expose local services to WireGuard network"
        echo "Make sure WG_DOCKER_ALLOWED_HOSTS is set in your .env file"
        echo "Current mode:"
        curl -s $API_BASE/status | jq '.client_mode'
        ;;
    mode-proxy)
        echo "=== Switching to PROXY mode ==="
        echo "Use this mode to access remote services from WireGuard network"
        echo "Make sure ACCESS_SERVICES is set in your .env file"
        echo "Current mode:"
        curl -s $API_BASE/status | jq '.client_mode'
        ;;
    mode-status)
        echo "=== Client Mode Status ==="
        curl -s $API_BASE/status | jq '.client_mode'
        ;;
    public-exposure)
        echo "=== Public Exposure Status ==="
        curl -s $API_BASE/status | jq '.public_exposure'
        ;;
    access-services)
        echo "=== Access Services Configuration ==="
        curl -s $API_BASE/status | jq '.access_services'
        ;;
    shared-services)
        echo "=== Shared Services Configuration ==="
        curl -s $API_BASE/status | jq '.shared_docker_services'
        ;;
    # Advanced debugging commands
    debug-all)
        echo "=== Comprehensive Debug Information ==="

        echo -e "\n1. WireGuard Status:"
        curl -s $API_BASE/status | jq .

        echo -e "\n2. Network Interfaces:"
        curl -s $API_BASE/debug/network | jq '.interfaces' | head -20

        echo -e "\n3. Routing Table:"
        curl -s $API_BASE/debug/routes | jq '.ipv4_routes' | head -20

        echo -e "\n4. iptables NAT Rules:"
        curl -s $API_BASE/debug/iptables | jq '.iptables_nat' | head -20

        echo -e "\n5. Docker Networks:"
        curl -s $API_BASE/debug/network | jq '.docker_networks'
        ;;
    test-connection)
        echo "=== Testing WireGuard Connection ==="

        # Check if WireGuard is connected
        STATUS=$(curl -s $API_BASE/status | jq -r '.status')
        if [ "$STATUS" = "connected" ]; then
            echo "✓ WireGuard is connected"

            # Test basic network connectivity
            echo -e "\nTesting network connectivity:"
            config=$(curl -s $API_BASE/config)
            wg_interface=$(echo "$config" | jq -r '.interface_name')
            wg_address=$(echo "$config" | jq -r '.address' | cut -d'/' -f1)

            echo "Interface: $wg_interface"
            echo "Address: $wg_address"

            # Test if interface exists
            if ip link show dev "$wg_interface" >/dev/null 2>&1; then
                echo "✓ Interface $wg_interface exists"
            else
                echo "✗ Interface $wg_interface not found"
            fi

            # Test if route exists
            if ip route show dev "$wg_interface" >/dev/null 2>&1; then
                echo "✓ Routes for $wg_interface exist"
            else
                echo "✗ No routes for $wg_interface"
            fi

        else
            echo "✗ WireGuard is not connected"
            echo "Current status: $STATUS"
        fi
        ;;
    restart)
        echo "=== Restarting WireGuard Connection ==="

        echo "1. Disconnecting..."
        curl -s -X POST $API_BASE/disconnect | jq '.status'

        sleep 2

        echo -e "\n2. Reconnecting..."
        curl -s -X POST $API_BASE/connect | jq '.status'

        echo -e "\n3. Final Status:"
        curl -s $API_BASE/status | jq '.status'
        ;;
    env-template)
        echo "=== Environment Template ==="
        echo "Creating .env template with all available options..."
        cat << 'EOF'
# Server Configuration
SERVER_PORT=8080
AUTO_CONNECT=false
CONFIG_PATH=/etc/wireguard
ENV_FILE_PATH=.env
DEBUG=false

# Client Mode (share/proxy/disabled)
CLIENT_MODE=share
ACCESS_SERVICES=10.7.0.2:80,10.7.0.2:443

# WireGuard Configuration
WG_INTERFACE_NAME=wg0
WG_PRIVATE_KEY=your_private_key_base64_here
WG_PUBLIC_KEY=your_public_key_base64_here
WG_ADDRESS=10.7.0.2/32
WG_DNS=192.168.30.1
WG_MTU=1420
WG_ENDPOINT=your.server.com:51820
WG_PEER_PUBLIC_KEY=server_public_key_base64_here
WG_PRESHARED_KEY=optional_preshared_key_base64_here
WG_ALLOWED_IPS=0.0.0.0/0,::/0
WG_PERSISTENT_KEEPALIVE=25

# Service Sharing (for CLIENT_MODE=share)
WG_DOCKER_ALLOWED_HOSTS=dummy:tcp:80,web:tcp:8080
WG_DOCKER_NETWORK=vpn-network
WG_DOCKER_FORWARD_TO_HOST=true
WG_SHARE_HOST_SERVICES=false
WG_HOST_SERVICES=tcp:80,tcp:443:8443

# Public Exposure (for CLIENT_MODE=proxy)
WG_ENABLE_PUBLIC_FORWARDING=true
WG_PUBLIC_PORTS=80:10.7.0.2:80,443:10.7.0.2:443
WG_PUBLIC_NETWORK=public-network
WG_PUBLIC_ALLOWED_CIDR=0.0.0.0/0
WG_LOG_PUBLIC_ACCESS=false

# Firewall Rules
WG_ALLOWED_TCP_PORTS=22,80,443,8080
WG_ALLOWED_UDP_PORTS=1194,51820
WG_ALLOW_ICMP=true

# Routing Configuration
WG_INTERFACE_ROUTING_MASK=24
WG_DISABLE_INTERFACE_ROUTING=false

# External Forwarding
WG_EXTERNAL_FORWARDING=tcp:8080:192.168.1.100:80,udp:1194:192.168.1.101:1194

# Logging
WG_LOG_ACCESS=false
EOF
        ;;
    help|--help|-h)
        echo "Usage: $0 {COMMAND}"
        echo ""
        echo "WireGuard Management Commands:"
        echo "  status                   - Show WireGuard status"
        echo "  connect                  - Connect to WireGuard"
        echo "  disconnect               - Disconnect from WireGuard"
        echo "  restart                  - Restart WireGuard connection"
        echo "  config                   - Show current configuration"
        echo "  test-connection          - Test WireGuard connection and network setup"
        echo ""
        echo "Key Management Commands:"
        echo "  generate-keys [true|false] - Generate new keys (optionally save to .env)"
        echo "  current-keys             - Show current public key info"
        echo "  private-key              - Generate private key (multiple formats)"
        echo "  private-key-simple       - Generate private key (plain text)"
        echo "  private-key-env          - Generate private key (env format)"
        echo "  public-key-simple        - Generate public key from current private key"
        echo ""
        echo "Client Mode Commands:"
        echo "  mode-share               - Info about SHARE mode (expose services)"
        echo "  mode-proxy               - Info about PROXY mode (access services)"
        echo "  mode-status              - Show current client mode"
        echo "  public-exposure          - Show public exposure status"
        echo "  access-services          - Show configured access services"
        echo "  shared-services          - Show configured shared services"
        echo ""
        echo "Debug Commands:"
        echo "  health                   - Health check"
        echo "  debug-endpoint           - Endpoint debugging info"
        echo "  debug-network            - Network interface and routing info"
        echo "  debug-keys               - Key conversion debugging"
        echo "  debug-iptables           - iptables rules debugging"
        echo "  debug-resolve            - DNS resolution debugging"
        echo "  debug-routes             - Routing table debugging"
        echo "  debug-all                - Comprehensive debug information"
        echo ""
        echo "Utility Commands:"
        echo "  logs                     - Show container logs (follow)"
        echo "  setup                    - Generate keys and save to .env"
        echo "  quick-connect            - Generate keys, save, and connect"
        echo "  env-template             - Show .env template with all options"
        echo "  help                     - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 setup                    # Generate keys and save to .env"
        echo "  $0 quick-connect            # Complete setup and connect"
        echo "  $0 generate-keys true       # Generate keys and save to .env"
        echo "  $0 private-key-simple       # Get private key for copy/paste"
        echo "  $0 public-key-simple        # Get public key for server config"
        echo "  $0 debug-network            # Debug network issues"
        echo "  $0 test-connection          # Test connection and routing"
        echo "  $0 mode-status              # Check current client mode"
        echo "  $0 env-template             # Create a complete .env template"
        echo ""
        echo "Client Mode Examples:"
        echo "  SHARE mode: Expose local services to WireGuard network"
        echo "    CLIENT_MODE=share WG_DOCKER_ALLOWED_HOSTS=web:tcp:80"
        echo ""
        echo "  PROXY mode: Access remote services and expose publicly"
        echo "    CLIENT_MODE=proxy ACCESS_SERVICES=10.7.0.2:80 WG_PUBLIC_PORTS=80:10.7.0.2:80"
        exit 0
        ;;
    *)
        echo "Error: Unknown command '$ACTION'"
        echo ""
        echo "Run '$0 help' for available commands"
        exit 1
        ;;
esac