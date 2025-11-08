# wg-service-proxy
wg-service-proxy is a flexible WireGuard-based service proxy that enables secure service exposure and access across distributed

## Architecture Overview
````
┌─────────────────┐    ┌───────────────────┐    ┌─────────────────┐
│   SHARE Client  │    │   WireGuard       │    │   PROXY Client  │
│  (10.7.0.2)     │◄──►│   Server          │◄──►│  (10.7.0.3)     │
│                 │    │                   │    │                 │
│ • CLIENT_MODE=  │    │ • Routes traffic  │    │ • CLIENT_MODE=  │
│   share         │    │   between clients │    │   proxy         │
│ • Exposes dummy │    │ • 192.168.30.224  │    │ • Accesses      │
│   service:80    │    │   :51820          │    │   remote services│
│ • WG: wg0       │    │                   │    │ • Exposes to    │
└─────────────────┘    └───────────────────┘    │   public        │
         │                                      │ • WG: wg0       │
         ▼                                      └─────────────────┘
┌─────────────────┐                                      │
│  Dummy Service  │                                      ▼
│  (internal)     │                            ┌─────────────────┐
│  port 80        │                            │   Public Users  │
└─────────────────┘                            │                 │
                                               │ • Access via    │
                                               │   proxy public IP│
                                               │ • port 80       │
                                               └─────────────────┘
````
## Detailed Flow
### 1. SHARE Client Setup (Service Exposer)
Environment (.env.share):
```
CLIENT_MODE=share
WG_INTERFACE_NAME=wg0
WG_ADDRESS=10.7.0.2/32
WG_DOCKER_ALLOWED_HOSTS=dummy:tcp:80
```
### Sharing Flow:
1. Startup: 
   WireGuard connects to server via wg0
2. Service Sharing: setupServiceSharing() detects CLIENT_MODE=share
3. Docker Forwarding: setupDockerAllowedHosts() sets up iptables rules:
   - dummy:tcp:80 → resolves to container IP
   - Creates DNAT: wg0:80 → dummy-container-ip:80
4. Result: Dummy service available at 10.7.0.2:80 on WireGuard network

### 2. PROXY Client Setup (Public Gateway)
Environment (.env.proxy):
```CLIENT_MODE=proxy
  WG_INTERFACE_NAME=wg0
  WG_ADDRESS=10.7.0.3/32
  ACCESS_SERVICES=10.7.0.2:80
  WG_ENABLE_PUBLIC_FORWARDING=true
  WG_PUBLIC_PORTS=80:10.7.0.2:80
```
### Proxy Flow:
1. Startup: WireGuard connects to server via wg0
2. Service Access: setupServiceAccess() detects CLIENT_MODE=proxy
   - Adds routes for 10.7.0.2
   - Allows forwarding to remote services
3. Public Exposure: setupPublicExposure() detects public forwarding
   - Auto-detects public-network bridge interface (e.g., br-1f7e04147076)
   - Creates iptables rules:
     br-xxx:80 → 10.7.0.2:80 via wg0
4. Result: Public can access proxy-client-public-ip:80 → routes to share client's dummy service

### Traffic Flow Steps
Internal WireGuard Traffic:
```
PROXY Client (10.7.0.3) → WireGuard Server → SHARE Client (10.7.0.2) → Dummy Service
↓
ACCESS_SERVICES=10.7.0.2:80
```
Public Traffic Flow:
```
Public User → PROXY Client Public IP:80 → public-network bridge → iptables DNAT → 
WireGuard (wg0) → WireGuard Server → SHARE Client (10.7.0.2) → Dummy Service
      ↓
WG_PUBLIC_PORTS=80:10.7.0.2:80
```
### API Endpoints Flow

Management via manage-vpn.sh:
```
# SHARE Client
./manage-vpn.sh mode-status          # Check client mode
./manage-vpn.sh shared-services      # See what's being shared
./manage-vpn.sh debug-network        # Debug network setup

# PROXY Client  
./manage-vpn.sh mode-status          # Check client mode
./manage-vpn.sh access-services      # See remote services
./manage-vpn.sh public-exposure      # Check public forwarding
./manage-vpn.sh test-connection      # Test end-to-end connectivity
```
### Check Status:
```
# On any client
./manage-vpn.sh status
# Returns:
{
  "status": "connected",
  "interface": "wg0", 
  "client_mode": "proxy",
  "public_exposure": true,
  "access_services": ["10.7.0.2:80"]
}
```

### Management Script:
```
# Check client mode
./manage-vpn.sh mode-status

# Test everything is working
./manage-vpn.sh test-connection

# Get complete environment template
./manage-vpn.sh env-template > .env.template

# Comprehensive debugging
./manage-vpn.sh debug-all

# Restart connection
./manage-vpn.sh restart
```
### manage-vpn.sh
#### Client mode usage examples
 - mode-share - Info about SHARE mode
 - mode-proxy - Info about PROXY mode
 - mode-status - Show current client mode
 - public-exposure - Show public exposure status
 - access-services - Show configured access services
 - shared-services - Show configured shared services
#### Advanced Debugging:
 - debug-all - Comprehensive debug information
 - test-connection - Test WireGuard connection and network setup
#### Utility Commands:
 - restart - Restart WireGuard connection
 - env-template - Show complete .env template with all options
 - help - Enhanced help with examples
## Key Benefits
1. Separation of Concerns:
   - SHARE clients focus on exposing services
   - PROXY clients focus on access and public exposure
2. Flexible Deployment:
   - Multiple SHARE clients can expose different services
   - Multiple PROXY clients can provide different public access points
3. Auto-Discovery:
   - Services automatically available via WireGuard IPs
   - No manual service registration needed
4. Security:
   - All traffic encrypted through WireGuard
   - Public exposure controlled per proxy client
## Example Use Cases
* ### Use Case 1: Internal Service Mesh
    ```
    SHARE Client A (10.7.0.2) - exposes API service :8080
    SHARE Client B (10.7.0.4) - exposes DB service :5432
    PROXY Client (10.7.0.3) - accesses both internally
    ```
* ### Use Case 2: Public Facing Service
    ```
    SHARE Client (10.7.0.2) - exposes web app :80 (internal only)
    PROXY Client (10.7.0.3) - exposes web app to public :80 & :443
    ```
* ## Use Case 3: Multi-Tier Architecture
    ```
    SHARE Clients (10.7.0.2-10) - various backend services
    PROXY Client (10.7.0.100) - public API gateway
    ```


