package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/docker/docker/api/types"
	_ "github.com/docker/docker/api/types/filters"
	_ "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Constants for configuration keys and default values
const (
	defaultServerPort          = "8080"
	defaultWireGuardInterface  = "wg0"
	defaultMTU                 = 1420
	defaultPersistentKeepalive = 25
	defaultDockerNetwork       = "vpn-network"
	defaultConfigPath          = "/etc/wireguard"
	defaultEnvFilePath         = ".env"
	defaultAddress             = "10.8.0.2/24,fdcc:ad94:bacf:61a4::cafe:2/112"
	defaultAllowedIPs          = "0.0.0.0/0,::/0"

	// Environment variable keys
	envServerPort            = "SERVER_PORT"
	envAutoConnect           = "AUTO_CONNECT"
	envConfigPath            = "CONFIG_PATH"
	envEnvFilePath           = "ENV_FILE_PATH"
	envDebug                 = "DEBUG"
	envWGInterfaceName       = "WG_INTERFACE_NAME"
	envWGPrivateKey          = "WG_PRIVATE_KEY"
	envWGPublicKey           = "WG_PUBLIC_KEY"
	envWGAddress             = "WG_ADDRESS"
	envWGDNS                 = "WG_DNS"
	envWGMTU                 = "WG_MTU"
	envWGEndpoint            = "WG_ENDPOINT"
	envWGPeerPublicKey       = "WG_PEER_PUBLIC_KEY"
	envWGPresharedKey        = "WG_PRESHARED_KEY"
	envWGAllowedIPs          = "WG_ALLOWED_IPS"
	envWGPersistentKeepalive = "WG_PERSISTENT_KEEPALIVE"
	envWGAllowICMP           = "WG_ALLOW_ICMP"
	envWGAllowedTCPPorts     = "WG_ALLOWED_TCP_PORTS"
	envWGAllowedUDPPorts     = "WG_ALLOWED_UDP_PORTS"
	envWGDockerAllowedHosts  = "WG_DOCKER_ALLOWED_HOSTS"
	envWGDockerNetwork       = "WG_DOCKER_NETWORK"
	envWGExternalForwarding  = "WG_EXTERNAL_FORWARDING"

	// Routing constants
	envWGInterfaceRoutingMask = "WG_INTERFACE_ROUTING_MASK"

	// Protocol constants
	protocolTCP  = "tcp"
	protocolUDP  = "udp"
	protocolICMP = "icmp"
	protocolBoth = "both"
	protocolAll  = "all"

	// WireGuard key length
	wireguardKeyLength = 32

	// Retry configuration
	maxContainerIPRetries = 5
	retryDelay            = 2 * time.Second

	// Client modes
	envClientMode     = "CLIENT_MODE"
	envAccessServices = "ACCESS_SERVICES"

	// Client mode values
	clientModeShare    = "share"
	clientModeProxy    = "proxy"
	clientModeDisabled = "disabled"

	// Default values
	defaultClientMode = clientModeDisabled
)

type WireGuardConfig struct {
	InterfaceName       string `json:"interface_name"`
	PrivateKey          string `json:"private_key"`
	PublicKey           string `json:"public_key"`
	Address             string `json:"address"`
	DNS                 string `json:"dns"`
	MTU                 int    `json:"mtu"`
	Endpoint            string `json:"endpoint"`
	PeerPublicKey       string `json:"peer_public_key"`
	PresharedKey        string `json:"preshared_key"`
	AllowedIPs          string `json:"allowed_ips"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
}

type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type GenerateKeysRequest struct {
	SaveToEnv bool `json:"save_to_env"`
}

type AppConfig struct {
	ServerPort  string
	AutoConnect bool
	ConfigPath  string
	EnvFilePath string
}

// Global variables for WireGuard connection
var (
	wgDevice    *device.Device
	wgConnected bool
)

func loadConfig() (*AppConfig, error) {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found, using environment variables")
	}

	config := &AppConfig{
		ServerPort:  getEnv(envServerPort, defaultServerPort),
		AutoConnect: getEnv(envAutoConnect, "false") == "true",
		ConfigPath:  getEnv(envConfigPath, defaultConfigPath),
		EnvFilePath: getEnv(envEnvFilePath, defaultEnvFilePath),
	}

	return config, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}

func getEnvList(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func getEnvBool(key string, defaultValue bool) bool {
	val := strings.ToLower(os.Getenv(key))
	if val == "true" {
		return true
	} else if val == "false" {
		return false
	}
	return defaultValue
}

// Mode

// getClientMode determines if this client is sharing services or accessing remote services
func getClientMode() string {
	mode := strings.ToLower(getEnv(envClientMode, defaultClientMode))
	switch mode {
	case clientModeShare, clientModeProxy:
		return mode
	default:
		return clientModeDisabled
	}
}

// getAccessServices returns the list of services to access in proxy mode
func getAccessServices() []string {
	return getEnvList(envAccessServices)
}

// setupClientMode configures the client based on its mode
func setupClientMode(config *WireGuardConfig) {
	mode := getClientMode()

	switch mode {
	case clientModeShare:
		log.Printf("Client mode: SHARE - exposing local services to WireGuard network via %s", config.InterfaceName)
		setupServiceSharing(config)

	case clientModeProxy:
		log.Printf("Client mode: PROXY - accessing remote services from WireGuard network via %s", config.InterfaceName)
		setupServiceAccess(config)

	default:
		log.Printf("Client mode: DISABLED - no special service routing via %s", config.InterfaceName)
	}
}

// setupServiceSharing exposes local services to other WireGuard peers
func setupServiceSharing(config *WireGuardConfig) {
	// Use existing WG_DOCKER_ALLOWED_HOSTS for service sharing
	setupDockerAllowedHosts(config.InterfaceName)

	// Additional: Share host services if configured
	if getEnvBool("WG_SHARE_HOST_SERVICES", false) {
		setupHostServiceSharing(config)
	}

	log.Printf("Service sharing enabled via %s - local services available to WireGuard peers", config.InterfaceName)
}

// setupHostServiceSharing exposes host services to WireGuard network
func setupHostServiceSharing(config *WireGuardConfig) {
	hostServices := getEnv("WG_HOST_SERVICES", "")
	if hostServices == "" {
		return
	}

	entries := strings.Split(hostServices, ",")
	for _, entry := range entries {
		parts := strings.Split(entry, ":")
		if len(parts) < 2 {
			continue
		}

		protocol := strings.ToLower(parts[0])
		port := parts[1]
		targetPort := port
		if len(parts) > 2 {
			targetPort = parts[2]
		}

		// Get host gateway IP (for host services)
		gatewayIP := getHostGateway()
		if gatewayIP == "" {
			gatewayIP = "172.17.0.1" // Docker default gateway
		}

		log.Printf("Sharing host service via %s: %s:%s -> %s:%s",
			config.InterfaceName, protocol, port, gatewayIP, targetPort)

		// Setup DNAT forwarding
		addNATDNATRule(config.InterfaceName, protocol, port, fmt.Sprintf("%s:%s", gatewayIP, targetPort))
		addForwardRule(config.InterfaceName, protocol, targetPort, gatewayIP)
	}
}

// getHostGateway gets the host gateway IP for Docker
func getHostGateway() string {
	cmd := exec.Command("sh", "-c", "ip route | grep default | awk '{print $3}'")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// setupServiceAccess configures access to remote WireGuard services
func setupServiceAccess(config *WireGuardConfig) {
	accessServices := getAccessServices()
	if len(accessServices) == 0 {
		log.Printf("No access services configured for proxy mode on %s", config.InterfaceName)
		return
	}

	log.Printf("Setting up access to %d remote services via %s", len(accessServices), config.InterfaceName)

	for _, service := range accessServices {
		setupRemoteServiceAccess(config, service)
	}
}

// setupRemoteServiceAccess configures access to a specific remote service
func setupRemoteServiceAccess(config *WireGuardConfig, service string) {
	// Format: peer_ip:port or peer_ip:port:protocol
	parts := strings.Split(service, ":")
	if len(parts) < 2 {
		log.Printf("Invalid service format: %s", service)
		return
	}

	peerIP := strings.TrimSpace(parts[0])
	port := strings.TrimSpace(parts[1])
	protocol := "tcp"
	if len(parts) > 2 {
		protocol = strings.TrimSpace(parts[2])
	}

	// Validate peer IP
	if net.ParseIP(peerIP) == nil {
		log.Printf("Invalid peer IP: %s", peerIP)
		return
	}

	log.Printf("Configuring access to %s:%s (%s) via %s", peerIP, port, protocol, config.InterfaceName)

	// Ensure route exists for the peer
	if err := addSpecificRoute(config.InterfaceName, peerIP+"/32"); err != nil {
		log.Printf("Warning: Failed to add route for %s via %s: %v", peerIP, config.InterfaceName, err)
	}

	// Allow outgoing connections to the service
	execIPTablesRule("-A", "FORWARD", "-o", config.InterfaceName, "-d", peerIP,
		"-p", protocol, "--dport", port, "-j", "ACCEPT")

	// Mark for logging (optional)
	if getEnvBool("WG_LOG_ACCESS", false) {
		execIPTablesRule("-A", "FORWARD", "-o", config.InterfaceName, "-d", peerIP,
			"-p", protocol, "--dport", port,
			"-j", "LOG", "--log-prefix", "WG-ACCESS: ")
	}

	log.Printf("Access configured for %s:%s (%s) via %s", peerIP, port, protocol, config.InterfaceName)
}

// setupPublicExposure forwards public ports to WireGuard services
func setupPublicExposure(config *WireGuardConfig) {
	if !getEnvBool("WG_ENABLE_PUBLIC_FORWARDING", false) {
		return
	}

	publicPorts := getEnv("WG_PUBLIC_PORTS", "")
	if publicPorts == "" {
		log.Printf("Public exposure enabled but no WG_PUBLIC_PORTS defined")
		return
	}

	// Use Docker network interface instead of hardcoded eth0
	publicInterface := getPublicNetworkInterface()

	log.Printf("Setting up public exposure on %s (public-network) for ports: %s", publicInterface, publicPorts)

	entries := strings.Split(publicPorts, ",")
	for _, entry := range entries {
		setupPublicPortForwarding(config, publicInterface, entry)
	}

	log.Printf("Public exposure configured for %d port mappings on %s", len(entries), publicInterface)
}

// setupPublicPortForwarding sets up DNAT for public port -> WireGuard service
func setupPublicPortForwarding(config *WireGuardConfig, publicInterface, mapping string) {
	// Format: public_port:wg_ip:wg_port
	parts := strings.Split(mapping, ":")
	if len(parts) != 3 {
		log.Printf("Invalid public port mapping: %s", mapping)
		return
	}

	publicPort := strings.TrimSpace(parts[0])
	wgIP := strings.TrimSpace(parts[1])
	wgPort := strings.TrimSpace(parts[2])
	protocol := "tcp"

	log.Printf("Public forwarding: %s:%s -> %s:%s via %s",
		publicInterface, publicPort, wgIP, wgPort, config.InterfaceName)

	// Clean up any existing rules first
	cleanupPublicPortForwarding(publicInterface, publicPort, wgIP, wgPort)

	// DNAT: Public traffic -> WireGuard service
	execIPTablesRule("-t", "nat", "-A", "PREROUTING",
		"-i", publicInterface,
		"-p", protocol,
		"--dport", publicPort,
		"-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%s", wgIP, wgPort))

	// Allow forwarding to WireGuard network
	execIPTablesRule("-A", "FORWARD",
		"-i", publicInterface,
		"-o", config.InterfaceName,
		"-p", protocol,
		"--dport", wgPort,
		"-d", wgIP,
		"-j", "ACCEPT")

	// Allow return traffic
	execIPTablesRule("-A", "FORWARD",
		"-i", config.InterfaceName,
		"-o", publicInterface,
		"-p", protocol,
		"--sport", wgPort,
		"-s", wgIP,
		"-j", "ACCEPT")

	// SNAT for return traffic (masquerade)
	execIPTablesRule("-t", "nat", "-A", "POSTROUTING",
		"-o", publicInterface,
		"-p", protocol,
		"--dport", wgPort,
		"-d", wgIP,
		"-j", "MASQUERADE")

	// Log public access if enabled
	if getEnvBool("WG_LOG_PUBLIC_ACCESS", false) {
		execIPTablesRule("-A", "INPUT",
			"-i", publicInterface,
			"-p", protocol,
			"--dport", publicPort,
			"-j", "LOG",
			"--log-prefix", "WG-PUBLIC: ")
	}

	log.Printf("Public port %s forwarded to %s:%s via %s", publicPort, wgIP, wgPort, publicInterface)
}

// cleanupPublicPortForwarding removes existing rules to avoid duplicates
func cleanupPublicPortForwarding(publicInterface, publicPort, wgIP, wgPort string) {
	protocol := "tcp"

	// Remove DNAT rule
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-i", publicInterface,
		"-p", protocol,
		"--dport", publicPort,
		"-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%s", wgIP, wgPort)).Run()

	// Remove forwarding rules
	exec.Command("iptables", "-D", "FORWARD",
		"-i", publicInterface,
		"-o", "wg0",
		"-p", protocol,
		"--dport", wgPort,
		"-d", wgIP,
		"-j", "ACCEPT").Run()

	exec.Command("iptables", "-D", "FORWARD",
		"-i", "wg0",
		"-o", publicInterface,
		"-p", protocol,
		"--sport", wgPort,
		"-s", wgIP,
		"-j", "ACCEPT").Run()

	// Remove SNAT rule
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-o", publicInterface,
		"-p", protocol,
		"--dport", wgPort,
		"-d", wgIP,
		"-j", "MASQUERADE").Run()
}

// setupPublicAccessControls restricts public access if needed
func setupPublicAccessControls(publicInterface string) {
	allowedCIDR := getEnv("WG_PUBLIC_ALLOWED_CIDR", "0.0.0.0/0")

	if allowedCIDR != "0.0.0.0/0" {
		log.Printf("Restricting public access to CIDR: %s", allowedCIDR)

		// Allow only from specific CIDR
		execIPTablesRule("-A", "INPUT",
			"-i", publicInterface,
			"-p", "tcp",
			"--dport", "80,443,8080,8082",
			"-s", allowedCIDR,
			"-j", "ACCEPT")

		// Drop everything else
		execIPTablesRule("-A", "INPUT",
			"-i", publicInterface,
			"-p", "tcp",
			"--dport", "80,443,8080,8082",
			"-j", "DROP")
	}
}

func getWireGuardConfigFromEnv() *WireGuardConfig {
	config := &WireGuardConfig{
		InterfaceName:       getEnv(envWGInterfaceName, defaultWireGuardInterface),
		PrivateKey:          strings.TrimSpace(os.Getenv(envWGPrivateKey)),
		PublicKey:           strings.TrimSpace(os.Getenv(envWGPublicKey)),
		Address:             getEnv(envWGAddress, defaultAddress),
		DNS:                 os.Getenv(envWGDNS),
		MTU:                 getEnvInt(envWGMTU, defaultMTU),
		Endpoint:            strings.TrimSpace(os.Getenv(envWGEndpoint)),
		PeerPublicKey:       strings.TrimSpace(os.Getenv(envWGPeerPublicKey)),
		PresharedKey:        strings.TrimSpace(os.Getenv(envWGPresharedKey)),
		AllowedIPs:          getEnv(envWGAllowedIPs, defaultAllowedIPs),
		PersistentKeepalive: getEnvInt(envWGPersistentKeepalive, defaultPersistentKeepalive),
	}

	// Generate public key from private key if not provided
	if config.PrivateKey != "" && config.PublicKey == "" {
		if publicKey, err := generatePublicKeyFromPrivate(config.PrivateKey); err == nil {
			config.PublicKey = publicKey
			log.Printf("Generated public key from private key: %s", publicKey)
		} else {
			log.Printf("Warning: Failed to generate public key from private key: %v", err)
		}
	}

	return config
}

// Convert base64 key to hex format for WireGuard Go IPC
func base64ToHex(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key is empty")
	}

	key = strings.TrimSpace(key)
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 key: %v", err)
	}

	if len(decoded) != wireguardKeyLength {
		return "", fmt.Errorf("invalid key length: %d, expected %d", len(decoded), wireguardKeyLength)
	}

	return hex.EncodeToString(decoded), nil
}

func generatePublicKeyFromPrivate(privateKeyBase64 string) (string, error) {
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}

	if len(privateKey) != wireguardKeyLength {
		return "", fmt.Errorf("invalid private key length: %d", len(privateKey))
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to generate public key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(publicKey), nil
}

func generateKeyPair() (*KeyPair, error) {
	privateKey := make([]byte, wireguardKeyLength)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %v", err)
	}

	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKey)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)

	return &KeyPair{
		PrivateKey: privateKeyBase64,
		PublicKey:  publicKeyBase64,
	}, nil
}

// Helper function to execute iptables commands with logging
func execIPTablesRule(args ...string) error {
	cmd := exec.Command("iptables", args...)
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: iptables command failed: %v (args: %v)", err, args)
		return err
	}
	return nil
}

// Helper function to add iptables NAT DNAT rule
func addNATDNATRule(interfaceName, protocol, port, destination string) {
	execIPTablesRule("-t", "nat", "-A", "PREROUTING", "-i", interfaceName, "-p", protocol, "--dport", port, "-j", "DNAT", "--to-destination", destination)
}

// Helper function to add iptables NAT SNAT rule (masquerade)
func addNATSNATRule(protocol, destIP, port string) {
	execIPTablesRule("-t", "nat", "-A", "POSTROUTING", "-p", protocol, "-d", destIP, "--dport", port, "-j", "MASQUERADE")
}

// Helper function to add iptables FORWARD rule
func addForwardRule(interfaceName, protocol, port, destIP string) {
	execIPTablesRule("-A", "FORWARD", "-i", interfaceName, "-p", protocol, "--dport", port, "-d", destIP, "-j", "ACCEPT")
}

// Helper function to add iptables INPUT rule
func addInputRule(interfaceName, protocol, port string) {
	execIPTablesRule("-A", "INPUT", "-i", interfaceName, "-p", protocol, "--dport", port, "-j", "ACCEPT")
}

func setupIPTablesMasquerade(interfaceName string) error {
	// Enable IP forwarding
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.forwarding=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.default.forwarding=1").Run()

	// NAT outbound
	execIPTablesRule("-t", "nat", "-A", "POSTROUTING", "-o", interfaceName, "-j", "MASQUERADE")

	// Forwarding
	execIPTablesRule("-A", "FORWARD", "-i", interfaceName, "-j", "ACCEPT")
	execIPTablesRule("-A", "FORWARD", "-o", interfaceName, "-j", "ACCEPT")

	// INPUT rules
	// Allow ICMP if enabled
	if getEnvBool(envWGAllowICMP, false) {
		execIPTablesRule("-A", "INPUT", "-i", interfaceName, "-p", protocolICMP, "-j", "ACCEPT")
	}

	// Allow TCP ports
	for _, port := range getEnvList(envWGAllowedTCPPorts) {
		addInputRule(interfaceName, protocolTCP, port)
	}

	// Allow UDP ports
	for _, port := range getEnvList(envWGAllowedUDPPorts) {
		addInputRule(interfaceName, protocolUDP, port)
	}

	log.Printf("IPTables rules configured for %s", interfaceName)
	return nil
}

func setupRouting(interfaceName, allowedIPs string) error {
	if allowedIPs == "" {
		return fmt.Errorf("allowedIPs is empty")
	}

	log.Printf("Running setupRouting for %s with AllowedIPs: %s", interfaceName, allowedIPs)

	// First, clean up any existing routes for this interface
	cleanupExistingRoutes(interfaceName)

	// Parse allowed IPs
	ips := strings.Split(allowedIPs, ",")

	routeCount := 0
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		log.Printf("Adding route: %s via %s", ip, interfaceName)

		// Handle default routes specially
		if ip == "0.0.0.0/0" || ip == "::/0" {
			if err := setupDefaultRoute(interfaceName, ip); err != nil {
				log.Printf("Warning: Failed to setup default route %s: %v", ip, err)
			} else {
				routeCount++
			}
			continue
		}

		// For specific routes
		if err := addSpecificRoute(interfaceName, ip); err != nil {
			log.Printf("Warning: Failed to add route %s: %v", ip, err)
		} else {
			routeCount++
		}
	}

	log.Printf("Successfully added %d routes for %s", routeCount, interfaceName)

	// Setup policy-based routing for better traffic control
	/*	if err := setupPolicyRouting(interfaceName); err != nil {
		log.Printf("Warning: Failed to setup policy routing: %v", err)
	}*/

	if err := setupWireguardRouting(interfaceName); err != nil {
		log.Printf("Warning: Failed to setup WireGuard peer routing: %v", err)
	}

	return nil
}

func cleanupExistingRoutes(interfaceName string) {
	log.Printf("Cleaning up existing routes for %s", interfaceName)

	// Remove all existing routes for this interface
	exec.Command("ip", "route", "flush", "dev", interfaceName).Run()
	exec.Command("ip", "-6", "route", "flush", "dev", interfaceName).Run()

	// Remove any policy routing rules for this interface
	exec.Command("ip", "rule", "del", "prio", "100").Run()
	exec.Command("ip", "rule", "del", "prio", "200").Run()

	log.Printf("Existing routes cleaned up for %s", interfaceName)
}

func setupDefaultRoute(interfaceName, ip string) error {
	if ip == "0.0.0.0/0" {
		log.Printf("Setting up IPv4 default route via %s", interfaceName)

		// Don't remove existing default routes - use policy routing instead
		// Add default route via WireGuard with a specific metric (lower priority than main default)
		cmd := exec.Command("ip", "route", "add", "default", "dev", interfaceName, "metric", "1000")
		if output, err := cmd.CombinedOutput(); err != nil {
			// If route exists, try to replace it
			if strings.Contains(string(output), "File exists") {
				exec.Command("ip", "route", "del", "default", "dev", interfaceName).Run()
				cmd = exec.Command("ip", "route", "add", "default", "dev", interfaceName, "metric", "1000")
				if output, err = cmd.CombinedOutput(); err != nil {
					log.Printf("Failed to add default route: %v, output: %s", err, string(output))
					return err
				}
			} else {
				log.Printf("Failed to add default route: %v, output: %s", err, string(output))
				return err
			}
		}

		log.Printf("IPv4 default route added via %s with metric 1000", interfaceName)

	} else if ip == "::/0" {
		log.Printf("Setting up IPv6 default route via %s", interfaceName)

		// For IPv6 - similar approach
		cmd := exec.Command("ip", "-6", "route", "add", "default", "dev", interfaceName, "metric", "1000")
		if output, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(output), "File exists") {
				exec.Command("ip", "-6", "route", "del", "default", "dev", interfaceName).Run()
				cmd = exec.Command("ip", "-6", "route", "add", "default", "dev", interfaceName, "metric", "1000")
				if output, err = cmd.CombinedOutput(); err != nil {
					log.Printf("Failed to add IPv6 default route: %v, output: %s", err, string(output))
					return err
				}
			} else {
				log.Printf("Failed to add IPv6 default route: %v, output: %s", err, string(output))
				return err
			}
		}

		log.Printf("IPv6 default route added via %s with metric 1000", interfaceName)
	}

	return nil
}

func setupPolicyRouting(interfaceName string) error {
	log.Printf("Setting up simplified policy-based routing for %s", interfaceName)

	// Get the VPN interface IP (IPv4)
	cmd := exec.Command("ip", "-4", "addr", "show", "dev", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Could not get VPN interface IP, skipping policy routing: %v", err)
		return nil
	}

	var vpnIP, vpnCIDR string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				vpnCIDR = parts[1]                      // e.g. 10.8.0.2/24
				vpnIP = strings.Split(parts[1], "/")[0] // e.g. 10.8.0.2
				break
			}
		}
	}

	if vpnIP == "" {
		log.Printf("Could not determine VPN IP, skipping policy routing")
		return nil
	}

	log.Printf("VPN interface IP: %s (CIDR: %s)", vpnIP, vpnCIDR)

	// Clean up any existing rules (ignore errors)
	exec.Command("ip", "rule", "del", "from", vpnIP, "table", "main").Run()
	exec.Command("ip", "rule", "del", "lookup", "100").Run()

	// Rule: traffic from the VPN interface IP uses main routing table
	cmd = exec.Command("ip", "rule", "add", "from", vpnIP, "table", "main")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Failed to add policy rule: %v, output: %s", err, string(output))
	} else {
		log.Printf("Added policy rule: from %s use main table", vpnIP)
	}

	tableNum := "100"

	// Flush and rebuild VPN routing table
	exec.Command("ip", "route", "flush", "table", tableNum).Run()

	// Extract network portion (e.g. 10.8.0.0/24) for reference if needed
	ip, ipnet, _ := net.ParseCIDR(vpnCIDR)
	log.Printf("VPN network: %s, IP: %s", ipnet.String(), ip.String())

	// Add default route via VPN interface
	cmd = exec.Command("ip", "route", "add", "default", "dev", interfaceName, "table", tableNum)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Failed to add route to custom table: %v, output: %s", err, string(output))
	} else {
		log.Printf("Added default route to %s in table %s", interfaceName, tableNum)
	}

	// Marked packets use VPN table
	cmd = exec.Command("ip", "rule", "add", "fwmark", "1", "table", tableNum)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Failed to add mark rule: %v, output: %s", err, string(output))
	} else {
		log.Printf("Added fwmark rule: mark 1 -> table %s", tableNum)
	}

	log.Printf("Policy routing setup completed for %s", interfaceName)
	return nil
}

func setupWireguardRouting(interfaceName string) error {
	//log.Printf("Setting up WireGuard peer routing for %s", interfaceName)

	if getEnvBool("WG_DISABLE_INTERFACE_ROUTING", false) {
		log.Printf("WireGuard interface routing disabled by environment")
		return nil
	}

	// Get routing mask from environment variable, default to 24
	routingMask := getEnvInt("WG_INTERFACE_ROUTING_MASK", 24)

	// Special case: 0 means don't add any WireGuard-specific routes
	if routingMask == 0 {
		log.Printf("WireGuard interface routing disabled (mask=0)")
		return nil
	}

	if routingMask < 0 || routingMask > 32 {
		log.Printf("Invalid routing mask %d, using default 24", routingMask)
		routingMask = 24
	}

	log.Printf("Setting up WireGuard peer routing for %s with mask /%d", interfaceName, routingMask)

	// Get the VPN interface IP to determine the subnet
	cmd := exec.Command("ip", "-4", "addr", "show", "dev", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Could not get VPN interface IP: %v", err)
		return nil
	}

	var vpnIP, vpnCIDR string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				vpnCIDR = parts[1]                      // e.g. 10.7.0.2/32
				vpnIP = strings.Split(parts[1], "/")[0] // e.g. 10.7.0.2
				break
			}
		}
	}

	if vpnIP == "" {
		log.Printf("Could not determine VPN IP")
		return nil
	}

	log.Printf("VPN interface IP: %s (CIDR: %s)", vpnIP, vpnCIDR)

	// Parse the IP
	ip := net.ParseIP(vpnIP).To4()
	if ip == nil {
		log.Printf("Not an IPv4 address: %s", vpnIP)
		return nil
	}

	// Determine what subnet to use based on the CIDR and configured mask
	_, ipNet, err := net.ParseCIDR(vpnCIDR)
	if err != nil {
		log.Printf("Invalid CIDR format %s: %v", vpnCIDR, err)
		return nil
	}

	ones, _ := ipNet.Mask.Size()

	var subnet string
	if ones <= routingMask {
		// If it's already the target mask or larger, use the existing network
		subnet = ipNet.String()
		log.Printf("Using existing subnet: %s", subnet)
	} else {
		// If it's smaller than target mask, expand it
		switch routingMask {
		case 24:
			subnet = fmt.Sprintf("%d.%d.%d.0/%d", ip[0], ip[1], ip[2], routingMask)
		case 16:
			subnet = fmt.Sprintf("%d.%d.0.0/%d", ip[0], ip[1], routingMask)
		case 8:
			subnet = fmt.Sprintf("%d.0.0.0/%d", ip[0], routingMask)
		default:
			// For other masks, calculate properly
			mask := net.CIDRMask(routingMask, 32)
			networkIP := ip.Mask(mask)
			subnet = fmt.Sprintf("%s/%d", networkIP.String(), routingMask)
		}
		log.Printf("Expanding to /%d subnet: %s", routingMask, subnet)
	}

	log.Printf("Adding route for WireGuard subnet: %s via %s", subnet, interfaceName)
	cmd = exec.Command("ip", "route", "add", subnet, "dev", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(output), "File exists") {
			log.Printf("WireGuard subnet route already exists: %s", subnet)
		} else {
			log.Printf("Failed to add WireGuard subnet route: %v, output: %s", err, string(output))
			return fmt.Errorf("failed to add WireGuard subnet route: %v", err)
		}
	} else {
		log.Printf("Successfully added WireGuard subnet route: %s", subnet)
	}

	return nil
}

func getDockerNetworkRanges() []string {
	var networks []string

	// Get all network interfaces
	cmd := exec.Command("ip", "route", "show")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			// Look for Docker network routes (they typically have 'proto kernel' and docker-like IPs)
			if (strings.Contains(line, "172.") || strings.Contains(line, "10.") || strings.Contains(line, "192.168.")) &&
				strings.Contains(line, "dev") &&
				!strings.Contains(line, "default") {
				// Extract the network range
				parts := strings.Fields(line)
				if len(parts) > 0 {
					networks = append(networks, parts[0])
				}
			}
		}
	}

	// Remove duplicates
	uniqueNetworks := make([]string, 0)
	seen := make(map[string]bool)
	for _, net := range networks {
		if !seen[net] {
			seen[net] = true
			uniqueNetworks = append(uniqueNetworks, net)
		}
	}

	return uniqueNetworks
}

func addSpecificRoute(interfaceName, ip string) error {
	if strings.Contains(ip, ":") {
		// IPv6 route
		cmd := exec.Command("ip", "-6", "route", "add", ip, "dev", interfaceName)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Check if route already exists
			if !strings.Contains(string(output), "File exists") {
				return fmt.Errorf("failed to add IPv6 route %s: %v, output: %s", ip, err, string(output))
			}
		}
	} else {
		// IPv4 route
		cmd := exec.Command("ip", "route", "add", ip, "dev", interfaceName)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Check if route already exists
			if !strings.Contains(string(output), "File exists") {
				return fmt.Errorf("failed to add IPv4 route %s: %v, output: %s", ip, err, string(output))
			}
		}
	}
	return nil
}

func getContainerIP(containerName, dockerNetwork string) string {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("Docker client error: %v", err)
		return ""
	}

	ctx := context.Background()
	contJSON, err := cli.ContainerInspect(ctx, containerName)
	if err != nil {
		log.Printf("Failed to inspect container %s: %v", containerName, err)
		return ""
	}

	if contJSON.NetworkSettings == nil {
		log.Printf("No network settings for container %s", containerName)
		return ""
	}

	// Try exact match first
	if netConf, ok := contJSON.NetworkSettings.Networks[dockerNetwork]; ok {
		return netConf.IPAddress
	}

	// Try partial match (in case network has project prefix)
	for networkName, netConf := range contJSON.NetworkSettings.Networks {
		if strings.Contains(networkName, dockerNetwork) {
			log.Printf("Found partial network match: %s for %s", networkName, dockerNetwork)
			return netConf.IPAddress
		}
	}

	// If no match found, log available networks
	log.Printf("Container %s not attached to network %s. Available networks:", containerName, dockerNetwork)
	for netName := range contJSON.NetworkSettings.Networks {
		log.Printf("  - %s", netName)
	}

	return ""
}

// setupPortForwarding configures iptables rules for port forwarding
func setupPortForwarding(interfaceName, protocol, port, targetIP string) {
	destination := targetIP + ":" + port
	addNATDNATRule(interfaceName, protocol, port, destination)
	addNATSNATRule(protocol, targetIP, port)
	addForwardRule(interfaceName, protocol, port, targetIP)
	addInputRule(interfaceName, protocol, port)
	log.Printf("NAT forwarding %s %s -> %s via %s", strings.ToUpper(protocol), port, destination, interfaceName)
}

func setupDockerAllowedHosts(interfaceName string) {
	allowedHosts := getEnv(envWGDockerAllowedHosts, "")
	if allowedHosts == "" {
		log.Println("No WG_DOCKER_ALLOWED_HOSTS defined, skipping")
		return
	}

	dockerNetwork := getEnv(envWGDockerNetwork, defaultDockerNetwork)
	log.Printf("Using Docker network: %s", dockerNetwork)

	entries := strings.Split(allowedHosts, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		log.Printf("Processing entry: %s", entry)
		parts := strings.Split(entry, ":")
		if len(parts) < 2 {
			log.Printf("Invalid WG_DOCKER_ALLOWED_HOSTS entry: %s", entry)
			continue
		}

		containerName := parts[0]
		protocol := protocolTCP // default
		portOrProto := parts[1]

		if len(parts) >= 3 {
			protocol = strings.ToLower(parts[1])
			portOrProto = parts[2]
		}

		log.Printf("Looking for container: %s on network: %s", containerName, dockerNetwork)

		// Use retry logic to handle container startup timing
		ip := getContainerIPWithRetry(containerName, dockerNetwork)
		if ip == "" {
			log.Printf("Could not resolve IP for container %s on network %s after retries", containerName, dockerNetwork)
			continue
		}

		log.Printf("Resolved container %s to IP %s on network %s", containerName, ip, dockerNetwork)

		// Apply rules based on protocol
		switch protocol {
		case protocolICMP:
			// Just allow ICMP traffic to the container
			execIPTablesRule("-A", "INPUT", "-i", interfaceName, "-p", protocolICMP, "-d", ip, "-j", "ACCEPT")
			execIPTablesRule("-A", "FORWARD", "-i", interfaceName, "-p", protocolICMP, "-d", ip, "-j", "ACCEPT")
			log.Printf("Allowed ICMP to %s (%s) via %s", containerName, ip, interfaceName)

		case protocolTCP, protocolUDP:
			// Only setup port forwarding for TCP/UDP
			setupPortForwarding(interfaceName, protocol, portOrProto, ip)

		case protocolBoth, protocolAll:
			setupPortForwarding(interfaceName, protocolTCP, portOrProto, ip)
			setupPortForwarding(interfaceName, protocolUDP, portOrProto, ip)

		default:
			log.Printf("Unknown protocol %s for container %s", protocol, containerName)
		}
	}
}

func getContainerIPWithRetry(containerName, dockerNetwork string) string {
	for i := 0; i < maxContainerIPRetries; i++ {
		ip := getContainerIP(containerName, dockerNetwork)
		if ip != "" {
			return ip
		}
		if i < maxContainerIPRetries-1 {
			log.Printf("Retry %d/%d for container %s on network %s", i+1, maxContainerIPRetries, containerName, dockerNetwork)
			time.Sleep(retryDelay)
		}
	}
	return ""
}

// getNetworkInterface gets the interface name for a Docker network
func getNetworkInterface(networkName string) string {
	// Method 1: Use docker network inspect
	cmd := exec.Command("docker", "network", "inspect", networkName, "--format", "{{.Id}}")
	networkID, err := cmd.Output()
	if err == nil {
		networkIDStr := strings.TrimSpace(string(networkID))
		if len(networkIDStr) >= 12 {
			interfacePrefix := "br-" + networkIDStr[:12]
			if interfaceExists(interfacePrefix) {
				return interfacePrefix
			}
		}
	}

	// Method 2: Look for bridge interfaces
	cmd = exec.Command("ip", "link", "show")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, networkName) || strings.Contains(line, "br-") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					iface := strings.TrimSpace(parts[1])
					if strings.HasPrefix(iface, "br-") || strings.Contains(iface, networkName) {
						if interfaceExists(iface) {
							return iface
						}
					}
				}
			}
		}
	}

	// Method 3: Fallback to default bridge
	if interfaceExists("docker0") {
		return "docker0"
	}

	log.Printf("Warning: Could not detect interface for network %s, using eth0 as fallback", networkName)
	return "eth0"
}

// interfaceExists checks if a network interface exists
func interfaceExists(interfaceName string) bool {
	cmd := exec.Command("ip", "link", "show", "dev", interfaceName)
	return cmd.Run() == nil
}

// getPublicNetworkInterface gets the interface for public-network
func getPublicNetworkInterface() string {
	return getNetworkInterface("public-network")
}

func setupExternalForwarding(interfaceName string) {
	forwardRules := getEnv(envWGExternalForwarding, "")
	if forwardRules == "" {
		return
	}

	entries := strings.Split(forwardRules, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.Split(entry, ":")
		if len(parts) != 4 {
			log.Printf("Invalid WG_EXTERNAL_FORWARDING entry: %s", entry)
			continue
		}

		protocol := parts[0]
		wgPort := parts[1]
		targetHost := parts[2]
		targetPort := parts[3]

		// DNAT rule
		addNATDNATRule(interfaceName, protocol, wgPort, targetHost+":"+targetPort)

		// Allow forwarding
		addForwardRule(interfaceName, protocol, targetPort, targetHost)

		log.Printf("External forwarding: %s %s -> %s:%s", strings.ToUpper(protocol), wgPort, targetHost, targetPort)
	}
}

// resolveEndpoint resolves FQDN to IP address if needed
func resolveEndpoint(endpoint string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("endpoint is empty")
	}

	// Check if endpoint is already an IP address
	if host, port, err := net.SplitHostPort(endpoint); err == nil {
		// If host is already an IP, return as-is
		if net.ParseIP(host) != nil {
			return endpoint, nil
		}

		// Resolve FQDN to IP
		log.Printf("Resolving FQDN: %s", host)
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", fmt.Errorf("failed to resolve %s: %v", host, err)
		}

		if len(ips) == 0 {
			return "", fmt.Errorf("no IP addresses found for %s", host)
		}

		// Prefer IPv4 if available
		var resolvedIP string
		for _, ip := range ips {
			if ip.To4() != nil {
				resolvedIP = ip.String()
				break
			}
		}

		// If no IPv4, use the first IP (IPv6)
		if resolvedIP == "" {
			resolvedIP = ips[0].String()
		}

		resolvedEndpoint := net.JoinHostPort(resolvedIP, port)
		log.Printf("Resolved %s to %s", endpoint, resolvedEndpoint)
		return resolvedEndpoint, nil
	}

	return "", fmt.Errorf("invalid endpoint format: %s", endpoint)
}

func connectWireGuardGo(config *WireGuardConfig) error {
	// Validate required fields
	if config.PrivateKey == "" {
		return fmt.Errorf("private key is required")
	}
	if config.PeerPublicKey == "" {
		return fmt.Errorf("peer public key is required")
	}
	if config.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}

	log.Printf("Starting WireGuard Go connection to %s via interface %s", config.Endpoint, config.InterfaceName)

	// Create the TUN device
	tun, err := tun.CreateTUN(config.InterfaceName, config.MTU)
	if err != nil {
		return fmt.Errorf("failed to create TUN device %s: %v", config.InterfaceName, err)
	}

	logLevel := device.LogLevelError
	if os.Getenv(envDebug) == "true" {
		logLevel = device.LogLevelVerbose
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, "wireguard-go"))

	privateKeyHex, err := base64ToHex(config.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to convert private key to hex: %v", err)
	}

	peerPublicKeyHex, err := base64ToHex(config.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to convert peer public key to hex: %v", err)
	}

	// Build UAPI config
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("private_key=%s\n", privateKeyHex))
	configBuilder.WriteString("replace_peers=true\n")
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", peerPublicKeyHex))
	configBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", config.Endpoint))

	// Split AllowedIPs properly
	if config.AllowedIPs != "" {
		allowedIPs := strings.Split(config.AllowedIPs, ",")
		for _, ip := range allowedIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
			}
		}
	}

	if config.PersistentKeepalive > 0 {
		configBuilder.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", config.PersistentKeepalive))
	}

	if config.PresharedKey != "" {
		presharedKeyHex, err := base64ToHex(config.PresharedKey)
		if err != nil {
			return fmt.Errorf("failed to convert preshared key to hex: %v", err)
		}
		configBuilder.WriteString(fmt.Sprintf("preshared_key=%s\n", presharedKeyHex))
	}

	configString := configBuilder.String()
	log.Printf("Applying WireGuard configuration to %s:\n%s", config.InterfaceName, configString)

	if err := dev.IpcSet(configString); err != nil {
		return fmt.Errorf("failed to configure device %s: %v", config.InterfaceName, err)
	}

	if err := dev.Up(); err != nil {
		return fmt.Errorf("failed to bring device %s up: %v", config.InterfaceName, err)
	}

	// Apply IP addresses at OS level
	if config.Address != "" {
		for _, addr := range strings.Split(config.Address, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				cmd := exec.Command("ip", "address", "add", addr, "dev", config.InterfaceName)
				if output, err := cmd.CombinedOutput(); err != nil {
					log.Printf("Warning: Failed to add address %s to %s: %v, output: %s", addr, config.InterfaceName, err, string(output))
				}
			}
		}
		cmd := exec.Command("ip", "link", "set", "up", "dev", config.InterfaceName)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: Failed to bring interface %s up: %v, output: %s", config.InterfaceName, err, string(output))
		}
	}

	// Setup routing and forwarding
	log.Printf("Setting up VPN routing via %s...", config.InterfaceName)
	if err := setupRouting(config.InterfaceName, config.AllowedIPs); err != nil {
		log.Printf("Warning: Failed to setup routing for %s: %v", config.InterfaceName, err)
	}

	// Setup iptables rules
	setupIPTablesMasquerade(config.InterfaceName)

	// Setup external forwarding
	setupExternalForwarding(config.InterfaceName)

	// Setup client mode (share/proxy/disabled)
	setupClientMode(config)

	// Setup public exposure if enabled
	setupPublicExposure(config)

	// Setup public access controls
	publicInterface := getEnv("WG_PUBLIC_INTERFACE", "eth0")
	setupPublicAccessControls(publicInterface)

	// Setup Docker forwarding (existing functionality)
	setupDockerAllowedHosts(config.InterfaceName)

	wgDevice = dev
	wgConnected = true

	log.Printf("WireGuard Go connection established: %s", config.InterfaceName)
	return nil
}

func disconnectWireGuardGo() error {
	if wgDevice != nil {
		wgDevice.Close()
		wgDevice = nil
	}
	wgConnected = false
	log.Println("WireGuard Go connection closed")
	return nil
}

func checkWireGuardStatus() bool {
	if wgDevice == nil {
		return false
	}

	// Check if interface exists using the configured interface name
	config := getWireGuardConfigFromEnv()
	cmd := exec.Command("ip", "link", "show", "dev", config.InterfaceName)
	return cmd.Run() == nil
}

func debugRouting(interfaceName string) {
	config := getWireGuardConfigFromEnv()
	if interfaceName == "" {
		interfaceName = config.InterfaceName
	}

	log.Printf("=== Routing Debug for %s ===", interfaceName)

	// Show all routes
	cmd := exec.Command("ip", "route", "show")
	if output, err := cmd.Output(); err == nil {
		log.Printf("IPv4 Routes:\n%s", string(output))
	}

	cmd = exec.Command("ip", "-6", "route", "show")
	if output, err := cmd.Output(); err == nil {
		log.Printf("IPv6 Routes:\n%s", string(output))
	}

	// Show interface-specific routes
	cmd = exec.Command("ip", "route", "show", "dev", interfaceName)
	if output, err := cmd.Output(); err == nil {
		log.Printf("Routes for %s:\n%s", interfaceName, string(output))
	}

	log.Printf("=== End Routing Debug ===")
}

func debugWireGuardRouting() {
	log.Printf("=== WireGuard Routing Debug ===")

	// Check current WireGuard configuration
	cmd := exec.Command("wg", "show")
	if output, err := cmd.Output(); err == nil {
		log.Printf("WireGuard Status:\n%s", string(output))
	}

	// Check all routes
	cmd = exec.Command("ip", "route", "show")
	if output, err := cmd.Output(); err == nil {
		log.Printf("All IPv4 Routes:\n%s", string(output))
	}

	// Check what's in the environment
	wgConfig := getWireGuardConfigFromEnv()
	log.Printf("WireGuard Config - AllowedIPs: %s", wgConfig.AllowedIPs)
	log.Printf("WireGuard Config - Endpoint: %s", wgConfig.Endpoint)

	log.Printf("=== End Routing Debug ===")
}

func main() {
	appConfig, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Auto-connect if configured
	if appConfig.AutoConnect {
		wgConfig := getWireGuardConfigFromEnv()
		if wgConfig.PrivateKey != "" && wgConfig.Endpoint != "" && wgConfig.PeerPublicKey != "" {
			log.Println("Auto-connecting to WireGuard using Go implementation...")
			if err := connectWireGuardGo(wgConfig); err != nil {
				log.Printf("Auto-connect failed: %v", err)
			} else {
				log.Println("Auto-connect successful!")
				// Setup Docker forwarding rules after successful auto-connect
				setupDockerAllowedHosts(wgConfig.InterfaceName)
			}
		} else {
			log.Println("Auto-connect skipped: missing required configuration")
		}
	}
	// Register HTTP handlers
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/connect", connectHandler)
	http.HandleFunc("/disconnect", disconnectHandler)
	http.HandleFunc("/config", configHandler)
	http.HandleFunc("/keys/generate", generateKeysHandler)
	http.HandleFunc("/keys/current", currentKeysHandler)
	http.HandleFunc("/keys/private", generatePrivateKeyHandler)
	http.HandleFunc("/keys/private/simple", generatePrivateKeySimpleHandler)
	http.HandleFunc("/keys/private/env", generatePrivateKeyEnvHandler)
	http.HandleFunc("/keys/public/simple", generatePublicKeySimpleHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/debug/endpoint", endpointDebugHandler)
	http.HandleFunc("/debug/network", networkDebugHandler)
	http.HandleFunc("/debug/keys", keyDebugHandler)
	http.HandleFunc("/debug/iptables", iptablesDebugHandler)
	http.HandleFunc("/debug/resolve", resolveDebugHandler)
	http.HandleFunc("/debug/routes", routeDebugHandler)

	log.Printf("Starting WireGuard Go application on :%s", appConfig.ServerPort)
	log.Fatal(http.ListenAndServe(":"+appConfig.ServerPort, nil))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	config := getWireGuardConfigFromEnv()
	connected := wgConnected && checkWireGuardStatus()

	clientMode := getClientMode()
	accessServices := getAccessServices()
	publicPorts := getEnv("WG_PUBLIC_PORTS", "")

	response := map[string]interface{}{
		"wireguard_go":    true,
		"status":          "connected",
		"connected":       connected,
		"timestamp":       time.Now().UTC(),
		"interface":       config.InterfaceName,
		"client_mode":     clientMode,
		"public_exposure": getEnvBool("WG_ENABLE_PUBLIC_FORWARDING", false),
	}

	if connected {
		response["status"] = "connected"
	} else {
		response["status"] = "disconnected"
	}

	// Add mode-specific information
	if clientMode == clientModeProxy {
		if len(accessServices) > 0 {
			response["access_services"] = accessServices
		}
		if publicPorts != "" {
			response["public_port_mappings"] = publicPorts
			response["public_interface"] = getEnv("WG_PUBLIC_INTERFACE", "eth0")
		}
	}

	if clientMode == clientModeShare {
		response["service_sharing"] = true
		if dockerHosts := getEnv(envWGDockerAllowedHosts, ""); dockerHosts != "" {
			response["shared_docker_services"] = dockerHosts
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var config WireGuardConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		// Use environment configuration
		envConfig := getWireGuardConfigFromEnv()
		if envConfig.PrivateKey == "" {
			http.Error(w, "Missing private key. Generate keys first or provide complete config.", http.StatusBadRequest)
			return
		}
		if envConfig.Endpoint == "" {
			http.Error(w, "Missing endpoint configuration.", http.StatusBadRequest)
			return
		}
		if envConfig.PeerPublicKey == "" {
			http.Error(w, "Missing peer public key configuration.", http.StatusBadRequest)
			return
		}
		config = *envConfig
	}

	// Generate public key from private if not provided
	if config.PrivateKey != "" && config.PublicKey == "" {
		publicKey, err := generatePublicKeyFromPrivate(config.PrivateKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to generate public key from private key: %v", err), http.StatusBadRequest)
			return
		}
		config.PublicKey = publicKey
	}

	// FIX: Proper error handling with return
	if err := connectWireGuardGo(&config); err != nil {
		log.Printf("Failed to connect WireGuard: %v", err)
		http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("WireGuard connected")
	setupDockerAllowedHosts(config.InterfaceName)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "connected",
		"interface":  config.InterfaceName,
		"public_key": config.PublicKey,
		"method":     "wireguard_go",
	})
}

func disconnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := disconnectWireGuardGo(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "disconnected",
		"method": "wireguard_go",
	})
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	config := getWireGuardConfigFromEnv()

	// Mask private key and preshared key for security
	maskedConfig := *config
	if maskedConfig.PrivateKey != "" {
		maskedConfig.PrivateKey = "***masked***"
	}
	if maskedConfig.PresharedKey != "" {
		maskedConfig.PresharedKey = "***masked***"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(maskedConfig)
}

func generateKeysHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req GenerateKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.SaveToEnv = false
	}

	keyPair, err := generateKeyPair()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating keys: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"private_key":  keyPair.PrivateKey,
		"public_key":   keyPair.PublicKey,
		"saved_to_env": req.SaveToEnv,
		"message":      "Keys generated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func currentKeysHandler(w http.ResponseWriter, r *http.Request) {
	config := getWireGuardConfigFromEnv()

	response := map[string]interface{}{
		"public_key":      config.PublicKey,
		"has_private_key": config.PrivateKey != "",
		"message":         "Note: Private key is not shown for security reasons.",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Handler to generate only a private key for easy copy/paste
func generatePrivateKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyPair, err := generateKeyPair()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating private key: %v", err), http.StatusInternalServerError)
		return
	}

	// Return in multiple formats for easy use
	response := map[string]interface{}{
		"private_key": keyPair.PrivateKey,
		"public_key":  keyPair.PublicKey,
		"formats": map[string]string{
			"env_format":     fmt.Sprintf("WG_PRIVATE_KEY=%s", keyPair.PrivateKey),
			"export_format":  fmt.Sprintf("export WG_PRIVATE_KEY=%s", keyPair.PrivateKey),
			"docker_compose": fmt.Sprintf("      - WG_PRIVATE_KEY=%s", keyPair.PrivateKey),
		},
		"message": "Private key generated successfully. Copy the WG_PRIVATE_KEY value or use the pre-formatted versions below.",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Simple handler that returns just the private key as plain text
func generatePrivateKeySimpleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyPair, err := generateKeyPair()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating private key: %v", err), http.StatusInternalServerError)
		return
	}

	// Return as plain text for easy copy/paste
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(keyPair.PrivateKey))
}

func generatePublicKeySimpleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the current configuration from environment
	config := getWireGuardConfigFromEnv()

	if config.PrivateKey == "" {
		http.Error(w, "No private key found in environment variables (WG_PRIVATE_KEY)", http.StatusBadRequest)
		return
	}

	// Generate public key from the private key in environment
	publicKey, err := generatePublicKeyFromPrivate(config.PrivateKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate public key from private key: %v", err), http.StatusBadRequest)
		return
	}

	// Return as plain text for easy copy/paste
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(publicKey))
}

// Handler that returns private key in env format
func generatePrivateKeyEnvHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyPair, err := generateKeyPair()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating private key: %v", err), http.StatusInternalServerError)
		return
	}

	// Return as environment variable format
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "WG_PRIVATE_KEY=%s\n", keyPair.PrivateKey)
	fmt.Fprintf(w, "WG_PUBLIC_KEY=%s\n", keyPair.PublicKey)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":                 "healthy",
		"timestamp":              time.Now().UTC(),
		"wireguard_go_connected": wgConnected && checkWireGuardStatus(),
		"service":                "running",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func keyDebugHandler(w http.ResponseWriter, r *http.Request) {
	config := getWireGuardConfigFromEnv()

	privateKeyHex, privErr := base64ToHex(config.PrivateKey)
	peerPublicKeyHex, peerErr := base64ToHex(config.PeerPublicKey)

	response := map[string]interface{}{
		"private_key_base64":     config.PrivateKey,
		"private_key_hex":        privateKeyHex,
		"private_key_error":      fmt.Sprintf("%v", privErr),
		"peer_public_key_base64": config.PeerPublicKey,
		"peer_public_key_hex":    peerPublicKeyHex,
		"peer_public_key_error":  fmt.Sprintf("%v", peerErr),
		"endpoint":               config.Endpoint,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func endpointDebugHandler(w http.ResponseWriter, r *http.Request) {
	config := getWireGuardConfigFromEnv()

	response := map[string]interface{}{
		"endpoint":       config.Endpoint,
		"endpoint_parts": strings.Split(config.Endpoint, ":"),
		"has_port":       strings.Contains(config.Endpoint, ":"),
		"raw_endpoint":   fmt.Sprintf("%q", config.Endpoint),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func iptablesDebugHandler(w http.ResponseWriter, r *http.Request) {
	results := make(map[string]string)

	// Get all iptables tables and chains
	tables := []string{"filter", "nat", "mangle", "raw"}

	for _, table := range tables {
		cmd := exec.Command("iptables", "-t", table, "-L", "-n", "-v")
		if output, err := cmd.Output(); err == nil {
			results[fmt.Sprintf("iptables_%s", table)] = string(output)
		} else {
			results[fmt.Sprintf("iptables_%s", table)] = fmt.Sprintf("Error: %v", err)
		}
	}

	// Get iptables-save output (complete ruleset)
	cmd := exec.Command("iptables-save")
	if output, err := cmd.Output(); err == nil {
		results["iptables_save"] = string(output)
	} else {
		results["iptables_save"] = fmt.Sprintf("Error: %v", err)
	}

	// Get IPv6 rules if available
	cmd = exec.Command("ip6tables-save")
	if output, err := cmd.Output(); err == nil {
		results["ip6tables_save"] = string(output)
	} else {
		// Don't show error for ip6tables if it's not available
		results["ip6tables_save"] = "IPv6 iptables not available or no rules"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func resolveDebugHandler(w http.ResponseWriter, r *http.Request) {
	config := getWireGuardConfigFromEnv()

	resolvedEndpoint, err := resolveEndpoint(config.Endpoint)

	response := map[string]interface{}{
		"original_endpoint": config.Endpoint,
		"resolved_endpoint": resolvedEndpoint,
		"resolution_error":  fmt.Sprintf("%v", err),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func routeDebugHandler(w http.ResponseWriter, r *http.Request) {
	results := make(map[string]string)

	// IPv4 routes
	cmd := exec.Command("ip", "route", "show")
	if output, err := cmd.Output(); err == nil {
		results["ipv4_routes"] = string(output)
	} else {
		results["ipv4_routes"] = fmt.Sprintf("Error: %v", err)
	}

	// IPv6 routes
	cmd = exec.Command("ip", "-6", "route", "show")
	if output, err := cmd.Output(); err == nil {
		results["ipv6_routes"] = string(output)
	} else {
		results["ipv6_routes"] = fmt.Sprintf("Error: %v", err)
	}

	// Routing table
	cmd = exec.Command("route", "-n")
	if output, err := cmd.Output(); err == nil {
		results["route_table"] = string(output)
	} else {
		results["route_table"] = fmt.Sprintf("Error: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func networkDebugHandler(w http.ResponseWriter, r *http.Request) {
	results := make(map[string]string)

	// Get all interfaces
	cmd := exec.Command("ip", "addr", "show")
	if output, err := cmd.Output(); err == nil {
		results["interfaces"] = string(output)
	}

	// Get Docker networks
	cmd = exec.Command("docker", "network", "ls")
	if output, err := cmd.Output(); err == nil {
		results["docker_networks"] = string(output)
	}

	// Get public network interface
	publicInterface := getPublicNetworkInterface()
	results["public_network_interface"] = publicInterface

	// Show iptables rules for public interface
	cmd = exec.Command("iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v")
	if output, err := cmd.Output(); err == nil {
		results["nat_prerouting"] = string(output)
	}

	// Show forwarding rules
	cmd = exec.Command("iptables", "-L", "FORWARD", "-n", "-v")
	if output, err := cmd.Output(); err == nil {
		results["forward_rules"] = string(output)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
