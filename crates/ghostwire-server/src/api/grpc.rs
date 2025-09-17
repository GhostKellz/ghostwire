/// gRPC server implementation for GhostWire coordination protocol
///
/// Provides high-performance binary protocol endpoints for:
/// - Node registration and authentication
/// - Heartbeat processing and health monitoring
/// - Network map distribution
/// - Real-time network updates (streaming)

use std::{net::SocketAddr, sync::Arc, time::SystemTime};
use tonic::{transport::Server, Request, Response, Status, Code};
use tracing::{info, warn, error, debug};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use futures::Stream;
use std::pin::Pin;

use crate::coordinator::Coordinator;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};

// Generated protobuf types
use ghostwire_proto::coordination::v1::{
    coordination_service_server::{CoordinationService, CoordinationServiceServer},
    *,
};

/// gRPC service implementation
pub struct GrpcCoordinationService {
    coordinator: Arc<Coordinator>,
}

impl GrpcCoordinationService {
    pub fn new(coordinator: Arc<Coordinator>) -> Self {
        Self { coordinator }
    }

    /// Convert protobuf endpoints to internal types
    fn convert_endpoints(&self, endpoints: Vec<Endpoint>) -> Vec<crate::coordinator::Endpoint> {
        endpoints
            .into_iter()
            .map(|ep| crate::coordinator::Endpoint {
                addr: ep.addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                endpoint_type: match ep.r#type() {
                    EndpointType::DirectIpv4 => crate::coordinator::EndpointType::DirectIPv4,
                    EndpointType::DirectIpv6 => crate::coordinator::EndpointType::DirectIPv6,
                    EndpointType::Stun => crate::coordinator::EndpointType::Stun,
                    EndpointType::Derp => crate::coordinator::EndpointType::Derp,
                    EndpointType::Unknown => crate::coordinator::EndpointType::Unknown,
                },
                preference: ep.preference.unwrap_or(100),
            })
            .collect()
    }

    /// Convert internal endpoints to protobuf types
    fn convert_endpoints_to_proto(&self, endpoints: &[crate::coordinator::Endpoint]) -> Vec<Endpoint> {
        endpoints
            .iter()
            .map(|ep| Endpoint {
                addr: ep.addr.to_string(),
                r#type: match ep.endpoint_type {
                    crate::coordinator::EndpointType::DirectIPv4 => EndpointType::DirectIpv4 as i32,
                    crate::coordinator::EndpointType::DirectIPv6 => EndpointType::DirectIpv6 as i32,
                    crate::coordinator::EndpointType::Stun => EndpointType::Stun as i32,
                    crate::coordinator::EndpointType::Derp => EndpointType::Derp as i32,
                    crate::coordinator::EndpointType::Unknown => EndpointType::Unknown as i32,
                },
                preference: Some(ep.preference),
            })
            .collect()
    }

    /// Convert protobuf node capabilities to internal types
    fn convert_capabilities(&self, caps: Option<NodeCapabilities>) -> crate::coordinator::NodeCapabilities {
        let caps = caps.unwrap_or_default();
        crate::coordinator::NodeCapabilities {
            can_derp: caps.can_derp,
            can_exit_node: caps.can_exit_node,
            supports_ipv6: caps.supports_ipv6,
            supports_pcp: caps.supports_pcp,
            supports_pmp: caps.supports_pmp,
            supports_upnp: caps.supports_upnp,
        }
    }

    /// Convert internal network map to protobuf
    fn convert_network_map_to_proto(&self, map: &crate::coordinator::NetworkMap) -> NetworkMap {
        NetworkMap {
            node_key: map.node_key.0.to_vec(),
            peers: map.peers.iter().map(|node| Node {
                id: node.id.to_string(),
                user_id: node.user_id.to_string(),
                name: node.name.clone(),
                public_key: node.public_key.0.to_vec(),
                ipv4: node.ipv4.to_string(),
                ipv6: node.ipv6.map(|ip| ip.to_string()),
                endpoints: self.convert_endpoints_to_proto(&node.endpoints),
                allowed_ips: node.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
                routes: node.routes.iter().map(|route| Route {
                    id: route.id.to_string(),
                    node_id: route.node_id.to_string(),
                    prefix: route.prefix.to_string(),
                    advertised: route.advertised,
                    enabled: route.enabled,
                    is_primary: route.is_primary,
                }).collect(),
                tags: node.tags.clone(),
                created_at: node.created_at.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() as i64,
                last_seen: node.last_seen.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() as i64,
                expires_at: node.expires_at.map(|t| t.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() as i64),
                online: node.online,
            }).collect(),
            dns: Some(DnsConfig {
                resolvers: map.dns.resolvers.clone(),
                domains: map.dns.domains.clone(),
                magic_dns: map.dns.magic_dns,
                routes: map.dns.routes.iter().map(|(domain, routes)| {
                    (domain.clone(), DnsRoutes {
                        resolvers: routes.resolvers.clone(),
                    })
                }).collect(),
            }),
            derp_map: Some(DerpMap {
                regions: map.derp_map.regions.iter().map(|(id, region)| {
                    (*id, DerpRegion {
                        region_id: region.region_id,
                        region_code: region.region_code.clone(),
                        region_name: region.region_name.clone(),
                        nodes: region.nodes.iter().map(|node| DerpNode {
                            name: node.name.clone(),
                            hostname: node.hostname.clone(),
                            port: node.port,
                            public_key: node.public_key.0.to_vec(),
                            stun_only: node.stun_only,
                            stun_port: node.stun_port,
                        }).collect(),
                    })
                }).collect(),
            }),
            packet_filters: map.packet_filters.iter().map(|filter| PacketFilter {
                src_ips: filter.src_ips.clone(),
                dst_ports: filter.dst_ports.iter().map(|range| PortRange {
                    first: range.start,
                    last: range.end,
                }).collect(),
            }).collect(),
            user_profiles: map.user_profiles.iter().map(|(id, profile)| {
                (id.to_string(), UserProfile {
                    id: profile.id.to_string(),
                    login_name: profile.login_name.clone(),
                    display_name: profile.display_name.clone(),
                    profile_pic_url: profile.profile_pic_url.clone(),
                })
            }).collect(),
            domain: map.domain.clone(),
            version: map.version,
        }
    }

    /// Extract session token from request metadata
    fn extract_session_token(&self, request: &Request<impl std::any::Any>) -> Result<String> {
        request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .map(|token| token.to_string())
            .ok_or_else(|| GhostWireError::authentication("Missing or invalid authorization header"))
    }

    /// Convert internal error to gRPC status
    fn map_error(&self, error: GhostWireError) -> Status {
        match error {
            GhostWireError::Authentication(_) => Status::new(Code::Unauthenticated, error.to_string()),
            GhostWireError::NotFound(_) => Status::new(Code::NotFound, error.to_string()),
            GhostWireError::Validation(_) => Status::new(Code::InvalidArgument, error.to_string()),
            GhostWireError::ResourceExhausted(_) => Status::new(Code::ResourceExhausted, error.to_string()),
            _ => Status::new(Code::Internal, "Internal server error"),
        }
    }
}

#[tonic::async_trait]
impl CoordinationService for GrpcCoordinationService {
    /// Register a new node in the network
    async fn register_node(
        &self,
        request: Request<RegisterNodeRequest>,
    ) -> std::result::Result<Response<RegisterNodeResponse>, Status> {
        let req = request.into_inner();
        debug!("Registering node: {}", req.name);

        // Validate public key
        if req.public_key.len() != 32 {
            return Err(Status::invalid_argument("Invalid public key length"));
        }

        let public_key = PublicKey(req.public_key.try_into()
            .map_err(|_| Status::invalid_argument("Invalid public key format"))?);

        // Convert request
        let registration_req = crate::coordinator::NodeRegistrationRequest {
            name: req.name,
            public_key,
            endpoints: self.convert_endpoints(req.endpoints),
            capabilities: self.convert_capabilities(req.capabilities),
            pre_auth_key: req.pre_auth_key,
            tags: req.tags,
        };

        // TODO: Extract user_id from authentication context
        let user_id = UserId::new(); // Placeholder

        // Register node
        match self.coordinator.register_node(user_id, registration_req).await {
            Ok(response) => {
                info!("Successfully registered node: {}", response.node.name);

                let network_map = self.convert_network_map_to_proto(&response.network_map);
                let derp_map = network_map.derp_map.clone().unwrap_or_default();

                Ok(Response::new(RegisterNodeResponse {
                    node_id: response.node.id.to_string(),
                    ipv4: response.node.ipv4.to_string(),
                    ipv6: response.node.ipv6.map(|ip| ip.to_string()),
                    session_token: response.session_token,
                    network_map: Some(network_map),
                    derp_map: Some(derp_map),
                }))
            }
            Err(e) => {
                warn!("Failed to register node: {}", e);
                Err(self.map_error(e))
            }
        }
    }

    /// Process node heartbeat and return network updates
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> std::result::Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();

        // Validate session token
        let session_token = self.extract_session_token(&request)
            .map_err(|e| self.map_error(e))?;

        let node_id = NodeId::parse(&req.node_id)
            .map_err(|_| Status::invalid_argument("Invalid node ID"))?;

        // Validate session
        if !self.coordinator.validate_session(&node_id, &session_token).await
            .map_err(|e| self.map_error(e))? {
            return Err(Status::unauthenticated("Invalid session token"));
        }

        // Convert heartbeat request
        let heartbeat = crate::coordinator::NodeHeartbeat {
            node_id: node_id.clone(),
            endpoints: self.convert_endpoints(req.endpoints),
            stats: req.stats.map(|s| crate::coordinator::NodeStats {
                rx_bytes: s.rx_bytes,
                tx_bytes: s.tx_bytes,
                active_connections: s.active_connections,
                latency_ms: s.latency_ms,
                packet_loss: s.packet_loss,
            }),
        };

        match self.coordinator.process_heartbeat(node_id, heartbeat).await {
            Ok(response) => {
                debug!("Processed heartbeat successfully");

                Ok(Response::new(HeartbeatResponse {
                    network_map: response.network_map.map(|map| self.convert_network_map_to_proto(&map)),
                    next_heartbeat_seconds: response.next_heartbeat_seconds,
                    messages: response.messages,
                }))
            }
            Err(e) => {
                warn!("Failed to process heartbeat: {}", e);
                Err(self.map_error(e))
            }
        }
    }

    /// Unregister a node from the network
    async fn unregister_node(
        &self,
        request: Request<UnregisterNodeRequest>,
    ) -> std::result::Result<Response<UnregisterNodeResponse>, Status> {
        let req = request.into_inner();

        // Validate session token
        let session_token = self.extract_session_token(&request)
            .map_err(|e| self.map_error(e))?;

        let node_id = NodeId::parse(&req.node_id)
            .map_err(|_| Status::invalid_argument("Invalid node ID"))?;

        // Validate session
        if !self.coordinator.validate_session(&node_id, &session_token).await
            .map_err(|e| self.map_error(e))? {
            return Err(Status::unauthenticated("Invalid session token"));
        }

        match self.coordinator.unregister_node(&node_id).await {
            Ok(()) => {
                info!("Successfully unregistered node: {}", node_id);
                Ok(Response::new(UnregisterNodeResponse {
                    success: true,
                    message: "Node unregistered successfully".to_string(),
                }))
            }
            Err(e) => {
                warn!("Failed to unregister node: {}", e);
                Err(self.map_error(e))
            }
        }
    }

    /// Get current network map
    async fn get_network_map(
        &self,
        request: Request<NetworkMapRequest>,
    ) -> std::result::Result<Response<NetworkMapResponse>, Status> {
        let req = request.into_inner();

        // Validate session token
        let session_token = self.extract_session_token(&request)
            .map_err(|e| self.map_error(e))?;

        let node_id = NodeId::parse(&req.node_id)
            .map_err(|_| Status::invalid_argument("Invalid node ID"))?;

        // Validate session
        if !self.coordinator.validate_session(&node_id, &session_token).await
            .map_err(|e| self.map_error(e))? {
            return Err(Status::unauthenticated("Invalid session token"));
        }

        match self.coordinator.get_network_map(&node_id, req.current_version).await {
            Ok((network_map, is_delta)) => {
                debug!("Generated network map for node: {}", node_id);

                Ok(Response::new(NetworkMapResponse {
                    network_map: Some(self.convert_network_map_to_proto(&network_map)),
                    is_delta,
                }))
            }
            Err(e) => {
                warn!("Failed to get network map: {}", e);
                Err(self.map_error(e))
            }
        }
    }

    /// Stream real-time network updates
    type StreamNetworkUpdatesStream = Pin<Box<dyn Stream<Item = std::result::Result<NetworkUpdateEvent, Status>> + Send>>;

    async fn stream_network_updates(
        &self,
        request: Request<StreamRequest>,
    ) -> std::result::Result<Response<Self::StreamNetworkUpdatesStream>, Status> {
        let req = request.into_inner();

        // Validate session token
        let session_token = self.extract_session_token(&request)
            .map_err(|e| self.map_error(e))?;

        let node_id = NodeId::parse(&req.node_id)
            .map_err(|_| Status::invalid_argument("Invalid node ID"))?;

        // Validate session
        if !self.coordinator.validate_session(&node_id, &session_token).await
            .map_err(|e| self.map_error(e))? {
            return Err(Status::unauthenticated("Invalid session token"));
        }

        // Create update stream
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // TODO: Implement real-time network updates subscription
        // For now, just close the stream immediately
        drop(tx);

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }
}

/// gRPC server wrapper
pub struct GrpcServer {
    coordinator: Arc<Coordinator>,
    addr: SocketAddr,
}

impl GrpcServer {
    pub fn new(coordinator: Arc<Coordinator>, addr: SocketAddr) -> Self {
        Self { coordinator, addr }
    }

    /// Start the gRPC server
    pub async fn serve(self) -> Result<()> {
        let service = GrpcCoordinationService::new(self.coordinator);

        info!("Starting gRPC server on {}", self.addr);

        Server::builder()
            .add_service(CoordinationServiceServer::new(service))
            .serve(self.addr)
            .await
            .map_err(|e| GhostWireError::network(format!("gRPC server failed: {}", e)))?;

        Ok(())
    }
}