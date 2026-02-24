package ghidraassist.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.io.FileWriter;

/**
 * Graph visualization panel using force-directed layout algorithm.
 * Renders function call graph with interactive features (zoom, pan, node dragging).
 */
public class GraphVisualizationPanel extends JPanel {
    private static final int MARGIN = 50;
    private static final int NODE_RADIUS = 15;
    private static final float REPULSIVE_FORCE = 100.0f;
    private static final float ATTRACTIVE_FORCE = 50.0f;
    private static final float DAMPING = 0.1f;

    private List<Node> nodes = new ArrayList<>();
    private List<Edge> edges = new ArrayList<>();
    private Map<String, Node> nodeMap = new HashMap<>();
    private List<List<String>> cycles = new ArrayList<>();

    private float zoom = 1.0f;
    private float offsetX = 0;
    private float offsetY = 0;
    private Point lastMousePos = null;
    private Node selectedNode = null;

    public GraphVisualizationPanel() {
        setBackground(Color.WHITE);
        setupMouseListeners();
    }

    private void setupMouseListeners() {
        MouseAdapter mouseAdapter = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                lastMousePos = e.getPoint();
                selectedNode = getNodeAt(e.getPoint());
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (e.isShiftDown() && lastMousePos != null) {
                    // Pan
                    offsetX += e.getX() - lastMousePos.x;
                    offsetY += e.getY() - lastMousePos.y;
                } else if (selectedNode != null) {
                    // Drag node
                    selectedNode.x = (e.getX() - offsetX) / zoom;
                    selectedNode.y = (e.getY() - offsetY) / zoom;
                }
                lastMousePos = e.getPoint();
                repaint();
            }

            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                float oldZoom = zoom;
                zoom *= (float) Math.pow(0.9, e.getWheelRotation());
                zoom = Math.max(0.1f, Math.min(5.0f, zoom));

                // Zoom towards cursor
                int x = e.getX();
                int y = e.getY();
                offsetX = x - (x - offsetX) * (zoom / oldZoom);
                offsetY = y - (y - offsetY) * (zoom / oldZoom);

                repaint();
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                lastMousePos = null;
                selectedNode = null;
            }
        };

        addMouseListener(mouseAdapter);
        addMouseMotionListener(mouseAdapter);
        addMouseWheelListener(mouseAdapter);
    }

    public void displayGraph(List<Map<String, Object>> nodeList, List<Map<String, Object>> edgeList,
                            List<List<String>> cycleList) {
        nodes.clear();
        edges.clear();
        nodeMap.clear();
        cycles = cycleList != null ? new ArrayList<>(cycleList) : new ArrayList<>();

        // Create nodes
        for (Map<String, Object> nodeData : nodeList) {
            Node node = new Node(
                (String) nodeData.get("id"),
                (String) nodeData.get("name"),
                ((Number) nodeData.get("in_degree")).intValue(),
                ((Number) nodeData.get("out_degree")).intValue(),
                ((Number) nodeData.get("size")).intValue()
            );
            nodes.add(node);
            nodeMap.put(node.id, node);
        }

        // Create edges
        for (Map<String, Object> edgeData : edgeList) {
            String source = (String) edgeData.get("source");
            String target = (String) edgeData.get("target");
            if (nodeMap.containsKey(source) && nodeMap.containsKey(target)) {
                edges.add(new Edge(nodeMap.get(source), nodeMap.get(target)));
            }
        }

        // Layout and render
        layoutGraph();
        repaint();
    }

    private void layoutGraph() {
        if (nodes.isEmpty()) return;

        // Initialize positions
        Random rand = new Random(42); // Fixed seed for reproducibility
        int width = getWidth() > 0 ? getWidth() : 400;
        int height = getHeight() > 0 ? getHeight() : 400;

        for (Node node : nodes) {
            node.x = MARGIN + rand.nextInt(Math.max(1, width - 2 * MARGIN));
            node.y = MARGIN + rand.nextInt(Math.max(1, height - 2 * MARGIN));
            node.vx = 0;
            node.vy = 0;
        }

        // Force-directed layout iterations
        int iterations = 100;
        for (int iter = 0; iter < iterations; iter++) {
            for (Node node : nodes) {
                double fx = 0, fy = 0;

                // Repulsive forces (node-node)
                for (Node other : nodes) {
                    if (node == other) continue;
                    double dx = node.x - other.x;
                    double dy = node.y - other.y;
                    double dist = Math.sqrt(dx * dx + dy * dy) + 0.1;
                    double force = REPULSIVE_FORCE / (dist * dist);
                    fx += (dx / dist) * force;
                    fy += (dy / dist) * force;
                }

                // Attractive forces (edges)
                for (Edge edge : edges) {
                    if (edge.from == node || edge.to == node) {
                        Node other = (edge.from == node) ? edge.to : edge.from;
                        double dx = other.x - node.x;
                        double dy = other.y - node.y;
                        double dist = Math.sqrt(dx * dx + dy * dy) + 0.1;
                        double force = (dist * dist) / ATTRACTIVE_FORCE;
                        fx += (dx / dist) * force;
                        fy += (dy / dist) * force;
                    }
                }

                // Update velocity and position
                node.vx = (node.vx + fx) * DAMPING;
                node.vy = (node.vy + fy) * DAMPING;
                node.x += node.vx;
                node.y += node.vy;

                // Boundary conditions
                node.x = Math.max(MARGIN, Math.min(node.x, width - MARGIN));
                node.y = Math.max(MARGIN, Math.min(node.y, height - MARGIN));
            }

            // Cooling schedule
            if (iter % 10 == 0) {
                for (Node node : nodes) {
                    node.vx *= 0.95;
                    node.vy *= 0.95;
                }
            }
        }
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2d = (Graphics2D) g;
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        // Apply transformations
        g2d.translate(offsetX, offsetY);
        g2d.scale(zoom, zoom);

        if (nodes.isEmpty()) {
            g2d.drawString("No graph data to display", 50, 50);
            return;
        }

        // Draw edges
        g2d.setColor(new Color(100, 100, 100, 200));
        g2d.setStroke(new BasicStroke(1.0f / zoom));
        for (Edge edge : edges) {
            // Check if edge is part of cycle
            boolean inCycle = isCycleEdge(edge.from.id, edge.to.id);
            if (inCycle) {
                g2d.setColor(new Color(255, 0, 0, 200)); // Red for cycle edges
            } else {
                g2d.setColor(new Color(100, 100, 100, 200));
            }
            g2d.drawLine(
                (int) edge.from.x, (int) edge.from.y,
                (int) edge.to.x, (int) edge.to.y
            );

            // Draw arrow head
            drawArrowHead(g2d, edge.from, edge.to);
        }

        // Draw nodes
        for (Node node : nodes) {
            int radius = Math.max(NODE_RADIUS, node.size / 4);

            // Calculate color based on importance
            int importance = Math.min(255, (node.inDegree + node.outDegree) * 20);
            Color nodeColor = new Color(50, 100 + importance / 2, 200);

            // Fill node
            g2d.setColor(nodeColor);
            g2d.fillOval((int) node.x - radius, (int) node.y - radius, 2 * radius, 2 * radius);

            // Node border (thicker for selected)
            g2d.setColor(node == selectedNode ? Color.RED : Color.BLACK);
            g2d.setStroke(new BasicStroke(node == selectedNode ? 3.0f / zoom : 2.0f / zoom));
            g2d.drawOval((int) node.x - radius, (int) node.y - radius, 2 * radius, 2 * radius);

            // Label
            g2d.setColor(Color.BLACK);
            g2d.setFont(new Font("Arial", Font.PLAIN, Math.max(7, (int) (10 / zoom))));
            FontMetrics fm = g2d.getFontMetrics();
            String label = node.name.length() > 15 ? node.name.substring(0, 12) + "..." : node.name;
            g2d.drawString(label, (int) node.x - fm.stringWidth(label) / 2, (int) node.y + 3);
        }

        // Draw legend
        drawLegend(g2d);
    }

    private void drawArrowHead(Graphics2D g2d, Node from, Node to) {
        double dx = to.x - from.x;
        double dy = to.y - from.y;
        double angle = Math.atan2(dy, dx);
        int arrowSize = 8;

        double endX = to.x - Math.cos(angle) * NODE_RADIUS;
        double endY = to.y - Math.sin(angle) * NODE_RADIUS;

        Polygon arrow = new Polygon();
        arrow.addPoint((int) endX, (int) endY);
        arrow.addPoint((int) (endX - arrowSize * Math.cos(angle - Math.PI / 6)),
                      (int) (endY - arrowSize * Math.sin(angle - Math.PI / 6)));
        arrow.addPoint((int) (endX - arrowSize * Math.cos(angle + Math.PI / 6)),
                      (int) (endY - arrowSize * Math.sin(angle + Math.PI / 6)));

        g2d.fillPolygon(arrow);
    }

    private void drawLegend(Graphics2D g2d) {
        int x = (int) (10 / zoom) + (int) (offsetX / zoom);
        int y = (int) (30 / zoom) + (int) (offsetY / zoom);
        g2d.setFont(new Font("Arial", Font.PLAIN, 10));
        g2d.setColor(Color.BLACK);

        g2d.drawString("Shift + Drag: Pan | Wheel: Zoom | Drag Node: Move", x, y);
        g2d.drawString("Red edges: Circular dependencies", x, y + 15);
    }

    private boolean isCycleEdge(String from, String to) {
        for (List<String> cycle : cycles) {
            for (int i = 0; i < cycle.size() - 1; i++) {
                if (cycle.get(i).equals(from) && cycle.get(i + 1).equals(to)) {
                    return true;
                }
            }
        }
        return false;
    }

    private Node getNodeAt(Point p) {
        for (Node node : nodes) {
            float screenX = (float) (node.x * zoom) + offsetX;
            float screenY = (float) (node.y * zoom) + offsetY;
            float radius = NODE_RADIUS * zoom;
            if (Math.hypot(p.x - screenX, p.y - screenY) <= radius) {
                return node;
            }
        }
        return null;
    }

    public void exportToJSON(java.io.File file) throws Exception {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"nodes\": [\n");

        for (int i = 0; i < nodes.size(); i++) {
            Node node = nodes.get(i);
            json.append(String.format(
                "    {\"id\": \"%s\", \"name\": \"%s\", \"in_degree\": %d, \"out_degree\": %d}",
                node.id, node.name, node.inDegree, node.outDegree
            ));
            if (i < nodes.size() - 1) json.append(",");
            json.append("\n");
        }

        json.append("  ],\n");
        json.append("  \"edges\": [\n");

        for (int i = 0; i < edges.size(); i++) {
            Edge edge = edges.get(i);
            json.append(String.format(
                "    {\"source\": \"%s\", \"target\": \"%s\"}",
                edge.from.id, edge.to.id
            ));
            if (i < edges.size() - 1) json.append(",");
            json.append("\n");
        }

        json.append("  ],\n");
        json.append("  \"cycles\": [\n");

        for (int i = 0; i < cycles.size(); i++) {
            List<String> cycle = cycles.get(i);
            json.append("    [");
            for (int j = 0; j < cycle.size(); j++) {
                json.append("\"").append(cycle.get(j)).append("\"");
                if (j < cycle.size() - 1) json.append(", ");
            }
            json.append("]");
            if (i < cycles.size() - 1) json.append(",");
            json.append("\n");
        }

        json.append("  ]\n");
        json.append("}\n");

        try (FileWriter writer = new FileWriter(file)) {
            writer.write(json.toString());
        }
    }

    public void clear() {
        nodes.clear();
        edges.clear();
        cycles.clear();
        nodeMap.clear();
        repaint();
    }

    // Inner classes
    private static class Node {
        String id, name;
        double x, y;
        double vx = 0, vy = 0;
        int inDegree, outDegree, size;

        Node(String id, String name, int inDegree, int outDegree, int size) {
            this.id = id;
            this.name = name;
            this.inDegree = inDegree;
            this.outDegree = outDegree;
            this.size = size;
        }
    }

    private static class Edge {
        Node from, to;

        Edge(Node from, Node to) {
            this.from = from;
            this.to = to;
        }
    }
}
