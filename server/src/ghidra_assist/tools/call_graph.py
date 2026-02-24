"""Function dependency graph analysis tool for call chain visualization.

Tools:
    analyze_call_graph -- build and analyze function call dependencies:
        - Trace function call chains
        - Identify circular dependencies
        - Compute call depth and breadth
        - Suggest critical functions (high in/out degree)
        - Export graph for visualization
"""

from __future__ import annotations

from typing import Any, Dict, List, Set
from collections import defaultdict, deque

from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool, ToolCategory

_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


@register_tool
class AnalyzeCallGraph(BaseTool):
    name = "analyze_call_graph"
    description = (
        "Analyze function call dependencies and build a dependency graph. "
        "Identify call chains, circular dependencies, and critical functions. "
        "Export graph for visualization and dependency analysis."
    )
    category = ToolCategory.ANALYSIS

    async def execute(
        self,
        repository: str,
        program: str,
        root_function: str = "",
        max_depth: int = 5,
        include_external: bool = False,
    ) -> Dict[str, Any]:
        """
        Analyze function call dependencies.

        Args:
            repository: Repository name
            program: Program name
            root_function: Starting function for call chain (empty = analyze all)
            max_depth: Maximum recursion depth to trace (1-10)
            include_external: Include calls to external libraries

        Returns:
            Dict with:
            - nodes: List of functions with metrics (in_degree, out_degree, depth)
            - edges: List of call relationships
            - cycles: List of circular dependency chains
            - critical_functions: Functions with high call activity
            - graph_metrics: Overall graph statistics
        """
        try:
            cache = _get_cache()
            prog = cache.get_program(repository, program)
            bridge = cache.bridge

            # Validate parameters
            max_depth = min(max(1, max_depth), 10)

            # Get all functions
            functions = bridge.list_functions(prog)
            if not functions:
                return self._error("No functions found in program")

            func_names = {f.get("name", f.get("address", "unknown")) for f in functions}

            # Build call graph
            call_graph = self._build_call_graph(bridge, prog, functions, include_external)

            # Analyze from specific function or all
            if root_function:
                if root_function not in func_names:
                    return self._error(f"Function '{root_function}' not found")
                subgraph = self._extract_subgraph(
                    call_graph, root_function, max_depth
                )
            else:
                subgraph = call_graph

            # Compute metrics
            metrics = self._compute_metrics(subgraph)

            # Find cycles
            cycles = self._find_cycles(subgraph)

            # Identify critical functions
            critical = self._identify_critical_functions(subgraph, top_n=10)

            # Build nodes and edges for export
            nodes = self._build_node_list(subgraph, metrics)
            edges = self._build_edge_list(subgraph)

            return {
                "success": True,
                "root_function": root_function or "all",
                "function_count": len(nodes),
                "edge_count": len(edges),
                "nodes": nodes,
                "edges": edges,
                "cycles": cycles,
                "critical_functions": critical,
                "graph_metrics": {
                    "total_functions": len(subgraph),
                    "total_calls": sum(len(v) for v in subgraph.values()),
                    "avg_out_degree": metrics.get("avg_out_degree", 0.0),
                    "max_out_degree": metrics.get("max_out_degree", 0),
                    "cyclomatic_complexity": self._estimate_complexity(subgraph),
                },
                "analysis_note": (
                    f"Analyzed {len(nodes)} functions with max depth {max_depth}. "
                    f"Found {len(cycles)} circular dependencies. "
                    f"Export node/edge data for visualization in external tools."
                ),
            }

        except FileNotFoundError:
            return self._error(f"Program '{program}' not found")
        except Exception as exc:
            self.logger.exception("analyze_call_graph failed")
            return self._error(f"Call graph analysis failed: {exc}")

    @staticmethod
    def _build_call_graph(
        bridge, program, functions: List[Dict[str, Any]], include_external: bool
    ) -> Dict[str, Set[str]]:
        """Build adjacency list of function calls."""
        graph = defaultdict(set)

        for func in functions[:100]:  # Limit to first 100 for performance
            func_name = func.get("name", func.get("address", "unknown"))

            try:
                # Get xrefs from this function
                xrefs = bridge.get_xrefs_from(program, func_name)
                for xref in xrefs:
                    target = xref.get("to_addr", "unknown")
                    ref_type = xref.get("ref_type", "")

                    # Include only call references
                    if "call" in ref_type.lower() or xref.get("is_call", False):
                        if include_external or not target.startswith("0x"):
                            graph[func_name].add(target)
            except Exception:
                pass

        return graph

    @staticmethod
    def _extract_subgraph(
        graph: Dict[str, Set[str]], root: str, max_depth: int
    ) -> Dict[str, Set[str]]:
        """Extract subgraph reachable from root within max_depth."""
        subgraph = defaultdict(set)
        visited = set()
        queue = deque([(root, 0)])

        while queue:
            node, depth = queue.popleft()

            if node in visited or depth > max_depth:
                continue

            visited.add(node)
            neighbors = graph.get(node, set())

            for neighbor in neighbors:
                subgraph[node].add(neighbor)
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

        return dict(subgraph)

    @staticmethod
    def _compute_metrics(graph: Dict[str, Set[str]]) -> Dict[str, Any]:
        """Compute graph metrics."""
        if not graph:
            return {}

        out_degrees = [len(targets) for targets in graph.values()]
        total_edges = sum(out_degrees)

        metrics = {
            "avg_out_degree": total_edges / len(graph) if graph else 0.0,
            "max_out_degree": max(out_degrees) if out_degrees else 0,
            "min_out_degree": min(out_degrees) if out_degrees else 0,
        }

        # Compute in-degrees
        in_degrees = defaultdict(int)
        for node, targets in graph.items():
            for target in targets:
                in_degrees[target] += 1

        if in_degrees:
            degrees = list(in_degrees.values())
            metrics["max_in_degree"] = max(degrees)
            metrics["avg_in_degree"] = sum(degrees) / len(in_degrees)

        return metrics

    @staticmethod
    def _find_cycles(graph: Dict[str, Set[str]]) -> List[List[str]]:
        """Find circular dependencies using DFS."""
        cycles = []
        visited = set()
        rec_stack = set()

        def dfs(node: str, path: List[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor, path[:])
                elif neighbor in rec_stack:
                    # Found cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    if cycle not in cycles:
                        cycles.append(cycle)

            rec_stack.discard(node)

        # Run DFS from each unvisited node
        for node in graph:
            if node not in visited:
                dfs(node, [])

        return cycles

    @staticmethod
    def _identify_critical_functions(
        graph: Dict[str, Set[str]], top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """Identify functions with high call activity."""
        # Compute in/out degree for each function
        out_degree = {node: len(targets) for node, targets in graph.items()}

        in_degree = defaultdict(int)
        for node, targets in graph.items():
            for target in targets:
                in_degree[target] += 1

        # Compute importance score (combination of in/out degree)
        importance = {}
        for node in set(list(graph.keys()) + list(in_degree.keys())):
            out_d = out_degree.get(node, 0)
            in_d = in_degree.get(node, 0)
            # Higher score = more central to call chain
            importance[node] = (out_d * 0.4 + in_d * 0.6)

        # Sort by importance
        critical = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:top_n]

        return [
            {
                "name": name,
                "importance_score": round(score, 2),
                "in_degree": in_degree.get(name, 0),
                "out_degree": out_degree.get(name, 0),
                "role": (
                    "Entry point" if out_degree.get(name, 0) > in_degree.get(name, 0)
                    else "Utility/Worker" if in_degree.get(name, 0) >= 3
                    else "Leaf"
                ),
            }
            for name, score in critical
        ]

    @staticmethod
    def _build_node_list(
        graph: Dict[str, Set[str]], metrics: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Build list of nodes with metrics for visualization."""
        # Calculate in-degrees
        in_degree = defaultdict(int)
        for node, targets in graph.items():
            for target in targets:
                in_degree[target] += 1

        nodes = []
        for node in set(list(graph.keys()) + list(in_degree.keys())):
            out_d = len(graph.get(node, set()))
            in_d = in_degree.get(node, 0)

            nodes.append(
                {
                    "id": node,
                    "name": node,
                    "in_degree": in_d,
                    "out_degree": out_d,
                    "total_degree": in_d + out_d,
                    "size": max(10, min(100, 10 + (in_d + out_d) * 5)),
                }
            )

        return sorted(nodes, key=lambda x: x["total_degree"], reverse=True)

    @staticmethod
    def _build_edge_list(graph: Dict[str, Set[str]]) -> List[Dict[str, str]]:
        """Build list of edges for visualization."""
        edges = []
        for source, targets in graph.items():
            for target in targets:
                edges.append(
                    {
                        "source": source,
                        "target": target,
                        "type": "call",
                    }
                )

        return edges

    @staticmethod
    def _estimate_complexity(graph: Dict[str, Set[str]]) -> float:
        """Estimate cyclomatic complexity from call graph."""
        if not graph:
            return 0.0

        num_nodes = len(graph)
        num_edges = sum(len(targets) for targets in graph.values())

        # Simplified cyclomatic complexity: E - N + 2P
        # P = number of connected components (estimate as 1)
        if num_nodes == 0:
            return 0.0

        complexity = num_edges - num_nodes + 2
        return max(1.0, complexity)
