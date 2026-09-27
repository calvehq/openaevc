//! Small deterministic graph algorithms shared by the Active Change Graph and composition.
//! Edges are `(from, to)` pairs; all results are ordered deterministically.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn adjacency<N: Ord + Clone>(edges: &[(N, N)], reverse: bool) -> BTreeMap<N, BTreeSet<N>> {
    let mut adj: BTreeMap<N, BTreeSet<N>> = BTreeMap::new();
    for (a, b) in edges {
        let (x, y) = if reverse { (b, a) } else { (a, b) };
        adj.entry(x.clone()).or_default().insert(y.clone());
    }
    adj
}

/// If adding `new` to the graph creates a cycle, returns the shortest such cycle starting and
/// ending at `new.0` (e.g. `[a, b, ..., a]`).
pub fn cycle_with_edge<N: Ord + Clone>(edges: &[(N, N)], new: (N, N)) -> Option<Vec<N>> {
    let (from, to) = new;
    if from == to {
        return Some(vec![from.clone(), to]);
    }
    let adj = adjacency(edges, false);
    // BFS from `to` back to `from`: shortest path closes the shortest cycle.
    let mut prev: BTreeMap<N, N> = BTreeMap::new();
    let mut seen = BTreeSet::from([to.clone()]);
    let mut queue = VecDeque::from([to.clone()]);
    while let Some(n) = queue.pop_front() {
        if n == from {
            let mut path = vec![n.clone()];
            let mut cur = n;
            while let Some(p) = prev.get(&cur) {
                path.push(p.clone());
                cur = p.clone();
            }
            path.reverse();
            let mut cycle = vec![from.clone()];
            cycle.extend(path);
            return Some(cycle);
        }
        for next in adj.get(&n).into_iter().flatten() {
            if seen.insert(next.clone()) {
                prev.insert(next.clone(), n.clone());
                queue.push_back(next.clone());
            }
        }
    }
    None
}

/// Nodes reachable from `start` (excluding `start`), following edges forward or reversed.
pub fn closure<N: Ord + Clone>(edges: &[(N, N)], start: &N, reverse: bool) -> Vec<N> {
    let adj = adjacency(edges, reverse);
    let mut seen = BTreeSet::new();
    let mut stack = vec![start.clone()];
    while let Some(n) = stack.pop() {
        for next in adj.get(&n).into_iter().flatten() {
            if next != start && seen.insert(next.clone()) {
                stack.push(next.clone());
            }
        }
    }
    seen.into_iter().collect()
}

/// Deterministic topological order where an edge `(a, b)` means "a comes after b". Ties are
/// broken by node order. On a cycle, returns one cycle `[x, ..., x]` as the error.
pub fn topo_order<N: Ord + Clone>(nodes: &[N], edges: &[(N, N)]) -> Result<Vec<N>, Vec<N>> {
    let deps = adjacency(edges, false);
    let dependents = adjacency(edges, true);
    let mut remaining: BTreeMap<N, usize> = nodes
        .iter()
        .map(|n| {
            (
                n.clone(),
                deps.get(n)
                    .map_or(0, |d| d.iter().filter(|x| nodes.contains(x)).count()),
            )
        })
        .collect();
    let mut ready: BTreeSet<N> = remaining
        .iter()
        .filter(|(_, c)| **c == 0)
        .map(|(n, _)| n.clone())
        .collect();
    let mut out = Vec::with_capacity(nodes.len());
    while let Some(n) = ready.pop_first() {
        remaining.remove(&n);
        for d in dependents.get(&n).into_iter().flatten() {
            if let Some(c) = remaining.get_mut(d) {
                *c -= 1;
                if *c == 0 {
                    ready.insert(d.clone());
                }
            }
        }
        out.push(n);
    }
    if remaining.is_empty() {
        return Ok(out);
    }
    // Walk unresolved dependencies until a node repeats.
    let mut path: Vec<N> = vec![remaining.keys().next().cloned().expect("non-empty")];
    loop {
        let cur = path.last().expect("non-empty").clone();
        let next = deps
            .get(&cur)
            .into_iter()
            .flatten()
            .find(|x| remaining.contains_key(*x))
            .cloned()
            .expect("unresolved node has an unresolved dependency");
        if let Some(pos) = path.iter().position(|x| *x == next) {
            let mut cycle = path[pos..].to_vec();
            cycle.push(next);
            return Err(cycle);
        }
        path.push(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(edges: &[(u32, u32)]) -> Vec<(u32, u32)> {
        edges.to_vec()
    }

    #[test]
    fn detects_minimal_cycle_through_new_edge() {
        let edges = g(&[(1, 2), (2, 3), (3, 4), (2, 4)]);
        // Adding 4 -> 1 closes cycles 4-1-2-4 (len 3) and 4-1-2-3-4 (len 4); report the shortest.
        assert_eq!(cycle_with_edge(&edges, (4, 1)), Some(vec![4, 1, 2, 4]));
        assert_eq!(cycle_with_edge(&edges, (4, 5)), None);
        assert_eq!(cycle_with_edge(&edges, (3, 3)), Some(vec![3, 3]));
    }

    #[test]
    fn closure_forward_and_reverse() {
        let edges = g(&[(1, 2), (2, 3), (4, 3)]);
        assert_eq!(closure(&edges, &1, false), vec![2, 3]);
        assert_eq!(closure(&edges, &3, true), vec![1, 2, 4]);
        assert!(closure(&edges, &3, false).is_empty());
    }

    #[test]
    fn topological_order_is_deterministic_or_reports_cycle() {
        let nodes = vec![1, 2, 3, 4];
        // Edge (a, b) means a must come after b.
        let edges = g(&[(1, 2), (1, 3), (3, 4)]);
        assert_eq!(topo_order(&nodes, &edges).unwrap(), vec![2, 4, 3, 1]);
        let cyc = topo_order(&nodes, &g(&[(1, 2), (2, 1)])).unwrap_err();
        assert_eq!(cyc.first(), cyc.last());
        assert!(cyc.len() >= 3);
    }
}
