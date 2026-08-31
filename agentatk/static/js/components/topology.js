/**
 * AGENTATK Console — Attack Surface Topology Component (Vis.js DAG)
 */

let network = null;
let networkNodes = null;
let networkEdges = null;
let physicsEnabled = false;

export function renderTopology(graphData, onSelectNode) {
  const container = document.getElementById('vis-graph-canvas');
  if (!container) return;

  const rawNodes = graphData?.nodes || [];
  const rawEdges = graphData?.edges || [];

  const nodeCountBadge = document.getElementById('node-count-badge');
  if (nodeCountBadge) {
    nodeCountBadge.innerText = `${rawNodes.length} nodes`;
  }

  if (rawNodes.length === 0) {
    container.innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; color:#64748b; font-size:12px; gap:8px;">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><path d="m14.83 9.17 4.24-4.24"/><path d="m14.83 14.83 4.24 4.24"/><path d="m9.17 14.83-4.24 4.24"/></svg>
        <span>Awaiting autonomous attack surface discovery...</span>
      </div>
    `;
    return;
  }

  // Format Nodes for Security Topology
  const nodesArray = rawNodes.map(n => {
    const isSource = n.type === 'source';
    const tier = (n.metadata && n.metadata.tier) || 'Tier 1';
    const isTier0 = tier.includes('Tier 0') || tier.includes('Critical');
    const isTier1 = tier.includes('Tier 1') || tier.includes('Moderate');

    let shape = 'dot';
    let size = 15;
    let color = {
      background: '#0c2838',
      border: '#38bdf8',
      highlight: { background: '#0369a1', border: '#7dd3fc' }
    };

    if (isSource) {
      shape = 'dot';
      size = 14;
      color = {
        background: '#075985',
        border: '#38bdf8',
        highlight: { background: '#0284c7', border: '#bae6fd' }
      };
    } else {
      if (isTier0) {
        shape = 'diamond';
        size = 18;
        color = {
          background: '#450a0a',
          border: '#ef4444',
          highlight: { background: '#7f1d1d', border: '#f87171' }
        };
      } else if (isTier1) {
        shape = 'square';
        size = 15;
        color = {
          background: '#451a03',
          border: '#f59e0b',
          highlight: { background: '#78350f', border: '#fbbf24' }
        };
      } else {
        shape = 'box';
        size = 13;
        color = {
          background: '#131722',
          border: '#475569',
          highlight: { background: '#1e293b', border: '#94a3b8' }
        };
      }
    }

    return {
      id: n.id,
      label: n.label,
      shape: shape,
      size: size,
      color: color,
      font: {
        color: '#f8fafc',
        size: 11,
        face: "'Inter', sans-serif",
        strokeWidth: 2,
        strokeColor: '#07080b'
      },
      borderWidth: 2,
      shadow: { enabled: true, color: 'rgba(0,0,0,0.7)', size: 5, x: 2, y: 2 },
      title: `${n.type.toUpperCase()}: ${n.label} (${isSource ? 'Ingress Source' : tier})`
    };
  });

  // Format Edges
  const edgesArray = rawEdges.map(e => {
    let edgeColor = '#334155';
    let width = 1.2;
    let dashes = true;

    if (e.status === 'confirmed' || e.status === 'tested_vulnerable') {
      edgeColor = '#ef4444';
      width = 2.4;
      dashes = false;
    } else if (e.status === 'tested' || e.status === 'blocked' || e.status === 'resisted') {
      edgeColor = '#10b981';
      width = 1.5;
      dashes = false;
    }

    return {
      id: `${e.source}->${e.target}`,
      from: e.source,
      to: e.target,
      color: { color: edgeColor, highlight: '#38bdf8', opacity: 0.9 },
      width: width,
      dashes: dashes,
      arrows: { to: { enabled: true, scaleFactor: 0.55 } }
    };
  });

  if (typeof vis === 'undefined') {
    console.warn("vis-network is not loaded yet");
    return;
  }

  try {
    if (!network) {
      container.innerHTML = '';
      networkNodes = new vis.DataSet(nodesArray);
      networkEdges = new vis.DataSet(edgesArray);

      const options = {
        nodes: {
          scaling: { min: 12, max: 24 }
        },
        edges: {
          smooth: { type: 'continuous', roundness: 0.2 }
        },
        physics: {
          solver: 'forceAtlas2Based',
          forceAtlas2Based: {
            gravitationalConstant: -55,
            centralGravity: 0.012,
            springLength: 110,
            springConstant: 0.12,
            damping: 0.95
          },
          stabilization: { enabled: true, iterations: 160, updateInterval: 25 }
        },
        interaction: {
          hover: true,
          tooltipDelay: 100,
          zoomView: true,
          dragView: true
        }
      };

      network = new vis.Network(container, { nodes: networkNodes, edges: networkEdges }, options);

      network.once('stabilizationIterationsDone', function () {
        network.setOptions({ physics: { enabled: false } });
        physicsEnabled = false;
        const pBtn = document.getElementById('physics-btn');
        if (pBtn) pBtn.innerText = "Physics: Off";
        const gStat = document.getElementById('graph-status-text');
        if (gStat) gStat.innerText = "Stabilized & Pinned";
      });

      network.on('click', function (params) {
        if (params.nodes.length > 0 && typeof onSelectNode === 'function') {
          onSelectNode(params.nodes[0]);
        }
      });
    } else {
      networkNodes.clear();
      networkNodes.add(nodesArray);
      networkEdges.clear();
      networkEdges.add(edgesArray);
    }
  } catch (err) {
    console.error("Failed to render Vis Network:", err);
  }
}

export function resetTopologyView() {
  if (network) {
    network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
  }
}

export function toggleTopologyPhysics() {
  if (!network) return;
  physicsEnabled = !physicsEnabled;
  network.setOptions({ physics: { enabled: physicsEnabled } });
  const pBtn = document.getElementById('physics-btn');
  if (pBtn) pBtn.innerText = physicsEnabled ? "Physics: On" : "Physics: Off";
  const gStat = document.getElementById('graph-status-text');
  if (gStat) gStat.innerText = physicsEnabled ? "Dynamic Physics" : "Pinned";
}
