// Service catalog — source de vérité pour images, ports, variables d'env et topologie.
// Consommé par infra-config.js (_buildEdgeOpts, _buildAgentOpts, _buildAdminOpts)
// et par le wizard / les visualisations d'infrastructure.

window._gpxCatalog = (function() {

  const SERVICES = {
    edge: {
      label:       'Passerelle',
      image:       'ghcr.io/vincamok/goproxify/edge:preview',
      command:     'edge',
      restart:     'unless-stopped',
      svcName:     'goproxify-edge',
      volume:      'goproxify_edge_data',
      mountpoint:  '/etc/goproxify',
      ports: [
        { host: 80,   container: 80,   proto: 'tcp', label: 'HTTP'   },
        { host: 443,  container: 443,  proto: 'tcp', label: 'HTTPS'  },
        { host: 443,  container: 443,  proto: 'udp', label: 'HTTP/3', optional: true, key: 'http3' },
        { host: 8000, container: 8000, proto: 'tcp', label: 'API interne (plan de contrôle)' },
        { host: 8002, container: 8002, proto: 'tcp', label: 'Cluster Raft', optional: true, key: 'cluster' },
        { host: 2222, container: 2222, proto: 'tcp', label: 'SSH Portal', optional: true, key: 'portal' },
        { host: 8444, container: 8444, proto: 'tcp', label: 'Portail web', optional: true, key: 'portal' },
      ],
      env: [
        { key: 'GPX_IDENTITY_EDGE_NODE_NAME', required: true,  secret: false, default: 'goproxify-edge',
          description: "Nom du nœud passerelle dans l'Admin." },
        { key: 'GPX_PAIRING_SECRET',          required: true,  secret: true,
          description: 'Secret de couplage partagé avec Admin et Agents. Hex 32 octets.' },
        { key: 'GPX_ENGINE_LOG_LEVEL',        required: false, secret: false, default: 'info',
          description: 'Niveau de log : debug | info | warn | error.' },
        { key: 'GPX_CLUSTER_ENABLED',         required: false, secret: false, flag: 'cluster',
          description: 'Active le mode cluster HA.' },
        { key: 'GPX_CLUSTER_RAFT_PORT',       required: false, secret: false, flag: 'cluster', default: '8002',
          description: 'Port Raft interne (cluster).' },
        { key: 'GPX_CLUSTER_NODE_ID',         required: false, secret: false, flag: 'cluster',
          description: 'Identifiant unique du nœud dans le cluster.' },
        { key: 'GPX_CLUSTER_GROUP_NAME',      required: false, secret: false, flag: 'cluster', default: 'ha-1',
          description: 'Nom du groupe de cluster.' },
        { key: 'GPX_CLUSTER_PEERS',           required: false, secret: false, flag: 'cluster',
          description: 'Pairs Raft (host:port séparés par virgule).' },
        { key: 'GPX_PORTAL_ENABLED',          required: false, secret: false, flag: 'portal',
          description: 'Active le portail applicatif.' },
      ],
      networks: ['goproxify_net'],
      dependsOn: ['goproxify-admin'],
    },

    agent: {
      label:      'Agent',
      image:      'ghcr.io/vincamok/goproxify/agent:preview',
      command:    'agent',
      restart:    'unless-stopped',
      svcName:    'goproxify-agent',
      volume:     'goproxify_agent_data',
      mountpoint: '/etc/goproxify',
      ports: [],
      extraVolumes: [
        { host: '/var/run/docker.sock', container: '/var/run/docker.sock', readonly: true, runtime: 'docker' },
        { host: '/run/podman/podman.sock', container: '/run/podman/podman.sock', readonly: true, runtime: 'podman' },
      ],
      env: [
        { key: 'GPX_IDENTITY_AGENT_NODE_NAME',               required: false, secret: false, default: 'agent-<hex8> (persisté dans le volume)',
          description: "Nom lisible du nœud Agent dans l'Admin. Optionnel : sans lui un ID stable est auto-généré au premier démarrage et persisté dans /etc/goproxify/agent-node-id. Recommandé pour nommer l'agent lisiblement ou garantir la stabilité si le volume est recréé." },
        { key: 'GPX_CONTROL_PLANE_EDGE_ENDPOINT',            required: true,  secret: false, default: 'http://goproxify-edge:8000',
          description: "URL HTTP du plan de contrôle de la passerelle (port 8000). Réseau interne si même hôte, IP/domaine sinon." },
        { key: 'GPX_CONTROL_PLANE_ADMIN_ENDPOINT',           required: false, secret: false, default: 'http://goproxify-admin:9443',
          description: "URL de l'Admin pour le fallback d'appairage. Si l'appairage via la passerelle échoue (401, Passerelle pas encore prêt), l'agent tente l'Admin. Recommandé en production." },
        { key: 'GPX_PAIRING_SECRET',                    required: true,  secret: true,
          description: 'Même valeur que la passerelle.' },
        { key: 'GPX_IDENTITY_REGION',                   required: false, secret: false,
          description: 'Région géographique du nœud (affichage Admin).' },
        { key: 'GPX_DOCKER_RUNTIME',                    required: false, secret: false, flag: 'containerRuntime',
          description: 'Runtime conteneur : docker | podman.' },
        { key: 'GPX_NETWORK_MANAGEMENT_EDGE_CONTAINER_NAME', required: false, secret: false, flag: 'containerRuntime',
          description: "Nom du conteneur passerelle sur cet hôte (pour la gestion réseau Docker)." },
        { key: 'GPX_KUBERNETES_ENABLED',                required: false, secret: false, flag: 'k8s',
          description: 'Active le support Kubernetes.' },
        { key: 'GPX_PORTAINER_ENABLED',                 required: false, secret: false, flag: 'portainer',
          description: 'Active le connecteur Portainer.' },
        { key: 'GPX_PORTAINER_URL',                     required: false, secret: false, flag: 'portainer',
          description: 'URL de l\'API Portainer.' },
        { key: 'GPX_PORTAINER_API_KEY',                 required: false, secret: true,  flag: 'portainer',
          description: 'Clé API Portainer.' },
        { key: 'GPX_LOG_FORWARDING_ENABLED',            required: false, secret: false, flag: 'logFwd',
          description: 'Active le transfert de logs centralisé.' },
        { key: 'GPX_AUTOSCALE_ENABLED',                 required: false, secret: false, flag: 'autoscale',
          description: 'Active l\'autoscaling des services.' },
      ],
      networks: ['goproxify_net'],
      dependsOn: ['goproxify-edge'],
    },

    admin: {
      label:      'Admin',
      image:      'ghcr.io/vincamok/goproxify/admin:preview',
      command:    'admin',
      restart:    'unless-stopped',
      svcName:    'goproxify-admin',
      volume:     'goproxify_admin_data',
      mountpoint: '/etc/goproxify',
      ports: [
        { host: 9443, container: 9443, proto: 'tcp', label: 'Interface HTTPS Admin' },
      ],
      env: [
        { key: 'GPX_SECURITY_JWT_SECRET',     required: true,  secret: true,
          description: 'Secret JWT pour les sessions admin. Hex 32 octets.' },
        { key: 'GPX_PAIRING_SECRET',          required: true,  secret: true,
          description: 'Même valeur que la passerelle.' },
        { key: 'GPX_FIRST_ADMIN_EMAIL',       required: true,  secret: false, default: 'admin@example.com',
          description: 'Email du premier compte admin (créé au premier démarrage).' },
        { key: 'GPX_FIRST_ADMIN_PASSWORD',    required: true,  secret: true,
          description: 'Mot de passe du premier compte admin (min. 12 car.). Changez-le après le premier login.' },
        { key: 'GPX_IDENTITY_EDGE_NODE_NAME', required: true,  secret: false, default: 'goproxify-edge',
          description: 'Nom du nœud passerelle auquel l\'Admin se connecte. Doit correspondre à GPX_IDENTITY_EDGE_NODE_NAME de la passerelle.' },
        { key: 'GPX_SERVER_API_PORT',         required: false, secret: false, default: '9443',
          description: 'Port d\'écoute de l\'Admin.' },
      ],
      networks: ['goproxify_net'],
      dependsOn: [],
    },
  };

  const NETWORKS = {
    goproxify_net: {
      driver: 'bridge',
      note: 'Nom avec underscore (_) — spécifier "name:" dans compose pour éviter le préfixe automatique.',
    },
  };

  // Flux d'intercommunication entre services
  const INTERCOMS = [
    { from:'agent', to:'edge',    proto:'WebSocket', port:8000, path:'/internal/v1/ws/agent',          auth:'pairing', priority:1,
      description:'Canal temps réel (heartbeat, événements, ordres). Toujours initié par l\'Agent.' },
    { from:'agent', to:'edge',    proto:'HTTP',      port:8000, path:'/internal/v1/agent/heartbeat',   auth:'pairing', priority:2,
      description:'Heartbeat HTTP (fallback si WS inactif). Requiert GPX_IDENTITY_AGENT_NODE_NAME non vide.' },
    { from:'agent', to:'edge',    proto:'HTTP',      port:8000, path:'/internal/v1/agent/events',      auth:'pairing', priority:2,
      description:'Événements lifecycle (fallback HTTP).' },
    { from:'admin', to:'edge',    proto:'HTTP',      port:8000, path:'/internal/v1/*',                 auth:'pairing',
      description:'API admin : nœuds, proxies, logs, configuration.' },
    { from:'browser', to:'admin', proto:'HTTPS',     port:9443, path:'/*',                             auth:'JWT',
      description:'Interface d\'administration.' },
    { from:'internet', to:'edge', proto:'HTTP/HTTPS',port:'80/443', path:'/*',                         auth:'none',
      description:'Trafic utilisateur — reverse-proxy vers les services des agents.' },
  ];

  // Topologies de déploiement
  const TOPOLOGIES = {
    single_host: {
      label: 'Mono-hôte',
      services: ['admin','edge','agent'],
      agentEdgeEndpoint: 'http://goproxify-edge:8000',
      description: 'Tout sur le même hôte. Communication via réseau Docker interne.',
    },
    multi_host: {
      label: 'Multi-hôtes',
      services: ['admin+edge', 'agent...'],
      agentEdgeEndpoint: 'http://<ip-ou-domaine-edge>:8000',
      description: 'Passerelle+Admin sur un hôte, Agent(s) sur d\'autres. Le port 8000 de la passerelle doit être accessible depuis les hôtes agents (pare-feu).',
    },
  };

  // ── API publique ────────────────────────────────────────────────────────────

  function service(type) { return SERVICES[type] || null; }

  function image(type) { return (SERVICES[type] || {}).image || ''; }

  function envDefs(type) { return ((SERVICES[type] || {}).env || []); }

  function requiredEnvKeys(type) {
    return envDefs(type).filter(e => e.required).map(e => e.key);
  }

  function secretEnvKeys(type) {
    return envDefs(type).filter(e => e.secret).map(e => e.key);
  }

  function ports(type, flags) {
    flags = flags || {};
    return ((SERVICES[type] || {}).ports || []).filter(p => {
      if (!p.optional) return true;
      return !!flags[p.key];
    });
  }

  function portStrings(type, flags) {
    return ports(type, flags).map(p => `${p.host}:${p.container}${p.proto === 'udp' ? '/udp' : ''}`);
  }

  function svcName(type) { return (SERVICES[type] || {}).svcName || type; }

  function volumeName(type, customName) {
    const s = SERVICES[type];
    if (!s) return '';
    const base = customName || s.svcName;
    return `${base}_data:${s.mountpoint}`;
  }

  function netBlock() {
    return '\nnetworks:\n  goproxify_net:\n    driver: bridge';
  }

  function intercoms() { return INTERCOMS.slice(); }

  function topologies() { return Object.assign({}, TOPOLOGIES); }

  function serviceTypes() { return Object.keys(SERVICES); }

  function all() { return { services: SERVICES, networks: NETWORKS, intercoms: INTERCOMS, topologies: TOPOLOGIES }; }

  return { service, image, envDefs, requiredEnvKeys, secretEnvKeys, ports, portStrings, svcName, volumeName, netBlock, intercoms, topologies, serviceTypes, all };

})();
